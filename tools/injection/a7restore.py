# A7R3A Recovery / Restore Tool  (service-mode channel)
# SAFETY: restore defaults to DRY-RUN. Actual writes need --confirm.
#         Critical partitions (calibration/boot) need --force-critical.
#         Every write is followed by readback + SHA-256 verification.
# Usage:
#   python a7restore.py diagnose
#   python a7restore.py verify
#   python a7restore.py probe                 (safe: writes only to /tmp scratch)
#   python a7restore.py restore --part 15 --dry-run
#   python a7restore.py restore --part 15 --confirm
import sys, os, time, struct, json, hashlib, argparse, subprocess
sys.path.insert(0, r'E:\Agent\a7r3a-research\pmca-src\Sony-PMCA-RE-master')

DIR = r'E:\Agent\a7r3a-research'
DUMP = os.path.join(DIR, 'dump')
MANIFEST = os.path.join(DIR, 'dump-manifest.txt')
PARTS = {'1':8323072,'2':20971520,'3':50331648,'4':12582912,'5':62914560,'6':16777216,'7':8388608,'10':12582912,'12':41943040,'13':4194304,'15':314572800,'16':146800640,'17':104857600,'18':20971520,'23':2097152,'B0':4194304,'B1':4194304}
CRITICAL = {'2','B0','B1','1','5'}   # calibration + boot + updater + WBI
CHUNK = 262144

def log(m):
    print(time.strftime('%H:%M:%S') + ' ' + m, flush=True)

def sha(path):
    h = hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda: f.read(1<<20), b''):
            h.update(b)
    return h.hexdigest().upper()

def usb_state():
    ps = r"Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\VID_054C*' } | Select-Object -ExpandProperty InstanceId"
    try:
        r = subprocess.run(['powershell','-NoProfile','-Command',ps], capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            if 'PID_0D99' in line: return 'MSC (0D99) - normal mass storage'
            if 'PID_0336' in line: return 'SERVICE (0336) - service mode'
            if 'PID_03E2' in line: return 'UPDATER (03E2) - update mode'
            if 'VID_054C' in line: return 'Sony device: ' + line.strip()
        return 'NO Sony USB device (camera off / disconnected / deep brick)'
    except Exception as e:
        return 'query error: %r' % e

def cmd_diagnose(args):
    log('=== CAMERA STATE ===')
    log(usb_state())
    log('=== BACKUP STATUS ===')
    ok = 0
    for nm, sz in PARTS.items():
        p = os.path.join(DUMP, 'n%s.bin' % nm)
        if os.path.exists(p) and os.path.getsize(p) == sz:
            ok += 1
        else:
            log('  MISSING/BAD: n%s' % nm)
    log('backup partitions OK: %d/%d' % (ok, len(PARTS)))
    log('=== RECOVERY CHANNELS ===')
    log('  A. service mode (0336): proven working today')
    log('  B. updater mode (03E2): available, CRC-only chain')
    log('  C. BootROM serial: UNVERIFIED on CXD90045 (research needed)')
    log('=== BRICK LEVEL GUIDE ===')
    log('  soft brick   -> battery pull / settings reset / restore-settings')
    log('  system brick -> restore --part N (service mode)')
    log('  boot brick   -> updater SD recovery / BootROM serial (research)')

def cmd_verify(args):
    log('=== VERIFY BACKUP vs MANIFEST ===')
    man = {}
    if os.path.exists(MANIFEST):
        for line in open(MANIFEST, encoding='utf-8'):
            if 'sha256=' in line:
                nm = line.split()[0].lstrip('n')
                man[nm] = line.split('sha256=')[1].strip()
    allok = True
    for nm, sz in PARTS.items():
        p = os.path.join(DUMP, 'n%s.bin' % nm)
        if not os.path.exists(p):
            log('  n%-3s MISSING' % nm); allok = False; continue
        if os.path.getsize(p) != sz:
            log('  n%-3s SIZE BAD' % nm); allok = False; continue
        h = sha(p)
        expect = man.get(nm)
        if expect and h != expect:
            log('  n%-3s HASH MISMATCH' % nm); allok = False
        else:
            log('  n%-3s OK  %s' % (nm, h[:16]))
    log('ALL OK: %s' % allok)

# ---- service session helpers (proven) ----
def wait_msc(max_sec=600):
    t0 = time.time()
    while time.time() - t0 < max_sec:
        if '0D99' in usb_state(): return True
        time.sleep(5)
    return False

def term_exec(camera, cmd, wait=10.0, quiet=1.2):
    t0 = time.time()
    while time.time() - t0 < 1.0:
        if not camera.dev.readTerminal(): break
    camera.dev.writeTerminal((cmd + '\n').encode('latin1'))
    out = b''; t0 = time.time(); last = time.time()
    while time.time() - t0 < wait:
        d = camera.dev.readTerminal()
        if d: out += d; last = time.time()
        elif out and time.time() - last > quiet: break
        else: time.sleep(0.03)
    return out.decode('latin1','replace')

def jiritsu(camera, cmd, data=b''):
    resp, out = camera.dev.sendSenserPacket(0x40, struct.pack('<HH', 0x1001, cmd) + data)
    if resp or len(out) < 4: raise RuntimeError('bad resp')
    return struct.unpack_from('<I', out)[0], out[4:]

def jselect(camera, path):
    st, _ = jiritsu(camera, 15, b'\0' + path.encode('ascii') + b'\0')
    return st

def jread_raw(camera, path):
    st = jselect(camera, path)
    if st != 0: raise RuntimeError('select 0x%08X' % st)
    dev = camera.dev
    req = struct.pack('<HH', 0x1001, 17) + b'\0\xff\0'
    hdr = dev.SenserPacketHeader.pack(size=len(req), pFunc=0x40, sequence=dev._sequence, version=0, miconType=0, offsetType=0, response=0)
    dev.driver.write(hdr + req)
    d = dev._readAll(dev.SenserPacketHeader.size)
    h = dev.SenserPacketHeader.unpack(d)
    if h is None:
        dev._sequence += 1; raise RuntimeError('empty header')
    if h.sequence != dev._sequence:
        dev._sequence += 1; raise RuntimeError('seq')
    data = b''; rem = h.size
    while rem > 0:
        n = min(rem, CHUNK); data += dev._readAll(n); rem -= n
    dev._sequence += 1
    status = struct.unpack_from('<I', data)[0]
    if status != 0: raise RuntimeError('read 0x%08X' % status)
    return data[4:]

def jwrite(camera, path, data, prefix=b'\0\xff\0'):
    st = jselect(camera, path)
    if st != 0: raise RuntimeError('select 0x%08X' % st)
    st2, _ = jiritsu(camera, 16, prefix + data)
    return st2

def session(work):
    from pmca.commands.usb import senserShellCommand
    if not wait_msc():
        log('ABORT: camera not in MSC'); return False
    try:
        senserShellCommand(complete=work)
        return True
    except Exception as e:
        log('session error: %r' % e)
        return False

def cmd_probe(args):
    log('=== WRITE PROBE (safe: /tmp scratch only) ===')
    def work(camera):
        try: camera.dev.driver.backend.dev.default_timeout = 30000
        except AttributeError: pass
        log('HASP %d' % len(camera.readHasp()))
        # register scratch file
        st = jwrite(camera, '/tmp/probe.bin', b'INIT')
        log('register: 0x%08X' % st)
        # test write sizes
        for sz in [1024, 65536, 262144]:
            payload = bytes([(i*7) % 256 for i in range(sz)])
            try:
                st = jwrite(camera, '/tmp/probe.bin', payload)
                if st != 0:
                    log('write %d: status 0x%08X (FAIL)' % (sz, st)); continue
                back = jread_raw(camera, '/tmp/probe.bin')
                ok = (back == payload)
                log('write %d: OK readback match=%s (%d bytes)' % (sz, ok, len(back)))
            except Exception as e:
                log('write %d: EXC %r' % (sz, e))
                break
        # test offset-write semantics (prefix variants) at 256KB
        log('--- offset prefix probes (256KB payload) ---')
        payload = bytes([(i*13) % 256 for i in range(262144)])
        for prefix in [b'\0\x00\x01', b'\0\x01\x00', b'\x01\x00\x00']:
            try:
                st = jwrite(camera, '/tmp/probe.bin', payload, prefix=prefix)
                log('prefix %s: status 0x%08X' % (prefix.hex(), st))
            except Exception as e:
                log('prefix %s: EXC %r' % (prefix.hex(), e))
        # cleanup
        camera.setTerminalEnable(False); camera.setTerminalEnable(True); time.sleep(1)
        term_exec(camera, 'rm -f /tmp/probe.bin', wait=5)
        camera.setTerminalEnable(False)
        log('probe done, scratch cleaned')
    session(work)

def cmd_restore(args):
    nm = args.part
    if nm not in PARTS:
        log('unknown part %s' % nm); return
    src = os.path.join(DUMP, 'n%s.bin' % nm)
    if not os.path.exists(src) or os.path.getsize(src) != PARTS[nm]:
        log('ABORT: backup n%s missing/bad' % nm); return
    h = sha(src)
    log('=== RESTORE n%s (%d bytes) sha256=%s ===' % (nm, PARTS[nm], h[:16]))
    log('target: /dev/nflasha%s' % nm)
    if nm in CRITICAL:
        log('*** CRITICAL PARTITION (calibration/boot/updater/WBI) ***')
        if not args.force_critical:
            log('ABORT: requires --force-critical'); return
    if not args.confirm:
        log('DRY-RUN: no writes. Plan:')
        log('  1. stage backup to camera (Jiritsu 256KB chunks): /tmp if <=4MB else FAT32 SD')
        log('  2. verify chunk count, umount target, cat chunks -> /dev/nflasha%s' % nm)
        log('  3. readback partition in 256KB pieces, compare SHA-256 to backup')
        log('  4. cleanup staging')
        log('Re-run with --confirm to execute.')
        return
    log('CONFIRMED write. Executing restore...')
    src_size = PARTS[nm]
    h_src = h
    def work(camera):
        try: camera.dev.driver.backend.dev.default_timeout = 30000
        except AttributeError: pass
        log('HASP %d' % len(camera.readHasp()))
        camera.setTerminalEnable(False); camera.setTerminalEnable(True); time.sleep(1.2)
        term_exec(camera, '', wait=3)
        # choose staging area: /tmp (12MB) for small, SD mount for large
        if src_size <= 4*1048576:
            stage_dir = '/tmp'
        else:
            mounts = term_exec(camera, 'cat /proc/mounts', wait=6)
            import re as _re
            m = _re.search(r'/dev/mmcb\S*\s+(\S+)\s+vfat', mounts)
            if not m:
                log('ABORT: large partition needs SD card mounted (FAT32). Insert card.')
                camera.setTerminalEnable(False); return
            stage_dir = m.group(1)
        log('staging dir: %s' % stage_dir)
        term_exec(camera, 'rm -f %s/rchunk_*.bin %s/restore.bin' % (stage_dir, stage_dir), wait=6)
        # stage backup in 256KB chunks via Jiritsu write
        nchunks = (src_size + CHUNK - 1)//CHUNK
        with open(src,'rb') as f:
            for ci in range(nchunks):
                data = f.read(CHUNK)
                st = jwrite(camera, '%s/rchunk_%05d.bin' % (stage_dir, ci), data)
                if st != 0:
                    log('ABORT: chunk %d write status 0x%08X' % (ci, st))
                    camera.setTerminalEnable(False); return
                if ci % 100 == 0:
                    log('staged chunk %d/%d' % (ci+1, nchunks))
        # verify all chunks staged
        ls = term_exec(camera, 'ls %s/rchunk_*.bin' % stage_dir, wait=8)
        n_staged = ls.count('rchunk_')
        if n_staged != nchunks:
            log('ABORT: staged %d chunks != expected %d, refusing to write' % (n_staged, nchunks))
            camera.setTerminalEnable(False); return
        # umount target if mounted (avoid writing a live filesystem)
        term_exec(camera, 'umount /dev/nflasha%s' % nm, wait=8)
        # write chunks directly to partition in sorted order (zero-padded names)
        log('cat chunks -> /dev/nflasha%s' % nm)
        out = term_exec(camera, 'cat %s/rchunk_*.bin > /dev/nflasha%s' % (stage_dir, nm), wait=max(30, src_size//1048576))
        log(out.strip().replace('\n',' '))
        term_exec(camera, 'sync', wait=15)
        camera.setTerminalEnable(False); time.sleep(0.5)
        # readback verify (chunked read of the partition via a /tmp copy)
        log('readback verify...')
        camera.setTerminalEnable(True); time.sleep(1)
        term_exec(camera, 'dd if=/dev/nflasha%s of=%s/readback.bin bs=64k' % (nm, stage_dir), wait=max(30, src_size//1048576))
        camera.setTerminalEnable(False); time.sleep(0.5)
        rb_size = 0
        h_rb = hashlib.sha256()
        rb_chunks = (src_size + CHUNK - 1)//CHUNK
        # verify by reading the readback file in 256KB pieces (dd skip + jread)
        camera.setTerminalEnable(True); time.sleep(1)
        ok = True
        for ci in range(rb_chunks):
            term_exec(camera, 'dd if=%s/readback.bin of=/tmp/rb_piece.bin bs=64k count=4 skip=%d' % (stage_dir, ci*4), wait=8)
            camera.setTerminalEnable(False); time.sleep(0.3)
            try:
                piece = jread_raw(camera, '/tmp/rb_piece.bin')
            except Exception as e:
                log('readback chunk %d failed: %r' % (ci, e)); ok = False; break
            h_rb.update(piece)
            rb_size += len(piece)
            camera.setTerminalEnable(True); time.sleep(0.5)
        camera.setTerminalEnable(False)
        h_rb_hex = h_rb.hexdigest().upper()
        log('readback size=%d sha256=%s' % (rb_size, h_rb_hex[:16]))
        if ok and rb_size == src_size and h_rb_hex == h_src:
            log('RESTORE VERIFIED OK: n%s matches backup' % nm)
        else:
            log('!!! RESTORE VERIFY FAILED - do NOT power off, retry or seek help !!!')
        # cleanup staging
        camera.setTerminalEnable(True); time.sleep(1)
        term_exec(camera, 'rm -f %s/rchunk_*.bin %s/readback.bin /tmp/rb_piece.bin' % (stage_dir, stage_dir), wait=8)
        camera.setTerminalEnable(False)
        log('cleanup done')
    session(work)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd')
    sub.add_parser('diagnose')
    sub.add_parser('verify')
    sub.add_parser('probe')
    r = sub.add_parser('restore')
    r.add_argument('--part', required=True)
    r.add_argument('--confirm', action='store_true')
    r.add_argument('--dry-run', action='store_true')
    r.add_argument('--force-critical', action='store_true')
    args = ap.parse_args()
    if args.cmd == 'diagnose': cmd_diagnose(args)
    elif args.cmd == 'verify': cmd_verify(args)
    elif args.cmd == 'probe': cmd_probe(args)
    elif args.cmd == 'restore': cmd_restore(args)
    else: ap.print_help()

if __name__ == '__main__':
    main()
