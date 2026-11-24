# -*- coding: utf-8 -*-
"""直通服务模式：向当前 Sony USB 设备（含0994 HID）发 StartSenser vendor 请求，
   触发相机切到服务模式0336，再认证+回滚。无需海量存储模式。
   前提：当前 Sony 设备已装 libusb-win32/WinUSB 驱动（Zadig）。
"""
import sys, time, json, subprocess
sys.path.insert(0, r'E:\Agent\a7r3a-research')
sys.path.insert(0, r'E:\Agent\a7r3a-research\pmca-src\Sony-PMCA-RE-master')
import a7restore as R
from pmca.commands.usb import senserShellCommand
import usb.core, usb.util
import libusb_package
DIR=r'E:\Agent\a7r3a-research'
PY=r'C:\Users\18793\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe'
backend=libusb_package.get_libusb1_backend()
backup=json.load(open(DIR+r'\audit2\solidify_backup.json'))
subprocess.run([PY, DIR+r'\a7build_patchwriter.py'],check=True,capture_output=True)
pw=open(DIR+r'\patch_writer','rb').read()
order=['cave_exp','dispC','worker','cave_wk']; done=set()
def work(cam):
    try: cam.dev.driver.backend.dev.default_timeout=12000
    except: pass
    cam.setTerminalEnable(False); time.sleep(0.3); cam.setTerminalEnable(True); time.sleep(0.8)
    R.term_exec(cam,'',wait=2)
    R.jwrite(cam,'/tmp/jiritsu/pw',pw); time.sleep(0.2)
    R.term_exec(cam,'chmod +x /tmp/jiritsu/pw',wait=3)
    for name in order:
        if name in done: continue
        info=backup[name]; data=bytes.fromhex(info['orig']); p=info['phys']
        R.jwrite(cam,'/tmp/jiritsu/p.bin',data); time.sleep(0.2)
        R.term_exec(cam,'/tmp/jiritsu/pw /dev/nflasha15 0x%x /tmp/jiritsu/p.bin'%p,wait=5)
        done.add(name); print('  RESTORED %s'%name,flush=True)
    R.term_exec(cam,'sync',wait=3); cam.setTerminalEnable(False)

def send_start_senser():
    d=usb.core.find(idVendor=0x054c, backend=backend)
    if not d:
        print('libusb 看不到 Sony 设备（需先装 libusb 驱动）',flush=True); return False
    print('找到 Sony PID=0x%04x，发 StartSenser vendor 请求'%(d.idProduct),flush=True)
    try:
        d.ctrl_transfer(0x43, 1, 0x37ff, 0xd7aa, b'', timeout=3000)
        print('  StartSenser 已发送',flush=True)
    except Exception as e:
        print('  发送结果 %r（可能已触发切换）'%e,flush=True)
    return True

last=None
for attempt in range(3000):
    if len(done)==len(order): print('ALL RESTORED',flush=True); break
    d=usb.core.find(idVendor=0x054c, backend=backend)
    pid=d.idProduct if d else None
    if pid!=last:
        print('[%04d] libusb Sony PID=%s'%(attempt,('0x%04x'%pid) if pid else None),flush=True); last=pid
    if pid is not None:
        print('  -> 发现设备，发StartSenser+尝试senser',flush=True)
        for bm in (0x40, 0x41, 0x43, 0x42):
            try:
                d.ctrl_transfer(bm, 1, 0x37ff, 0xd7aa, b'', timeout=1500)
                print('  start req bm=0x%02x 成功'%bm,flush=True)
            except Exception as e:
                print('  start req bm=0x%02x %r'%(bm,e),flush=True)
        try:
            senserShellCommand(complete=work)
        except Exception as e:
            print('  senser err %r'%e,flush=True)
    time.sleep(0.1)
print('FINAL done=%s'%sorted(done),flush=True)
