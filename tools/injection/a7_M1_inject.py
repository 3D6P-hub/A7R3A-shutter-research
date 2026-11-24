# -*- coding: utf-8 -*-
"""M1 一体化注入（自动检测 PID + 校验 libObj 基址）：
   曝光 flag stub(dispC 0xa3628c→0x53cf5a, 写flag=1@0x070a47f8) +
   worker soundId=4 stub(0x82c5ec→0x53d000, flag==1→ObjMsg soundId=4)。
   RAM 补丁，拔电池即清零。前提：M0 已写 beeplist kind4=Kasha 且已拔电池冷启动。
   安全：注入前校验 dispC/worker 原始 prologue + libObj 基址==0x05dca000（flag 为绝对地址）。
"""
import sys, time, re
sys.path.insert(0, r'E:\Agent\a7r3a-research')
sys.path.insert(0, r'E:\Agent\a7r3a-research\pmca-src\Sony-PMCA-RE-master')
import a7restore as R
from pmca.commands.usb import senserShellCommand
DIR=r'E:\Agent\a7r3a-research'
log=R.log
DUMP=open(DIR+r'\n15_extracted\lib\libObj.so','rb').read()
EXP_STUB=open(DIR+r'\stub-exposure.bin','rb').read()   # 必须是 a7buildstub_flag.py 产物（安全flag版）
EXP_HOOK=open(DIR+r'\hook-exposure.bin','rb').read()
WK_STUB=open(DIR+r'\stub-worker.bin','rb').read()       # a7buildstub_worker_s4.py 产物（soundId=4）
WK_HOOK=open(DIR+r'\hook-worker.bin','rb').read()
EXP_HOOK_FILE=0xa3628c; EXP_CAVE_FILE=0x53cf5a
WK_HOOK_FILE=0x82c5ec;  WK_CAVE_FILE=0x53d000
EXPECT_BASE=0x05dca000
FLAG_RT=0x070a47f8

def rd512(cam,pid,page):
    R.term_exec(cam,'rm -f /tmp/jiritsu/v.bin',wait=4)
    for _ in range(3):
        R.term_exec(cam,'dd if=/proc/%d/mem of=/tmp/jiritsu/v.bin bs=512 skip=%d count=8 2>/dev/null'%(pid,page//512),wait=12)
        time.sleep(0.5); p=R.jread_raw(cam,'/tmp/jiritsu/v.bin')
        if len(p)==4096: break
    return p
def wr(cam,pid,page,data):
    R.jwrite(cam,'/tmp/jiritsu/wp.bin',data); time.sleep(0.5)
    R.term_exec(cam,'dd if=/tmp/jiritsu/wp.bin of=/proc/%d/mem bs=4096 seek=%d count=1'%(pid,page//4096),wait=12)
    time.sleep(0.5)

def work(cam):
    try: cam.dev.driver.backend.dev.default_timeout=30000
    except: pass
    cam.setTerminalEnable(False); time.sleep(1); cam.setTerminalEnable(True); time.sleep(2)
    R.term_exec(cam,'',wait=3)
    # 1) 自动检测 im.elf PID（原始 cmdline，NUL 保留，PC 解析；busybox 无 tr）
    sh=b"#!/bin/sh\nfor p in /proc/[0-9]*; do\n  pid=${p#/proc/}\n  echo \"PID=$pid\"\n  cat $p/cmdline 2>/dev/null\n  echo \"\"\ndone\n"
    R.jwrite(cam,'/tmp/jiritsu/clraw.sh',sh); time.sleep(0.4)
    R.term_exec(cam,'chmod +x /tmp/jiritsu/clraw.sh',wait=5)
    R.term_exec(cam,'/tmp/jiritsu/clraw.sh > /tmp/jiritsu/clraw.txt 2>/dev/null',wait=30)
    time.sleep(0.5)
    txt=R.jread_raw(cam,'/tmp/jiritsu/clraw.txt').decode('latin1','replace')
    pid=None
    for blk in txt.split('PID=')[1:]:
        p=blk.split('\n',1)[0].strip()
        body=blk.split('\n',1)[1] if '\n' in blk else ''
        if 'im.elf' in body.replace('\x00',' '):
            pid=int(p); break
    log('im.elf PID=%s'%pid)
    if pid is None: log('ABORT: no im.elf PID found'); cam.setTerminalEnable(False); return
    # 2) 读 maps 校验 libObj 基址
    R.term_exec(cam,'cat /proc/%d/maps > /tmp/jiritsu/mm.txt 2>/dev/null'%pid,wait=8)
    time.sleep(0.4)
    maps=R.jread_raw(cam,'/tmp/jiritsu/mm.txt').decode('latin1','replace')
    base=None
    for line in maps.splitlines():
        if 'libObj.so' in line and 'r-xp' in line:
            base=int(line.split('-')[0],16); break
    log('PID=%d libObj r-xp base=0x%x (expect 0x%x)'%(pid,base or 0,EXPECT_BASE))
    if base!=EXPECT_BASE:
        log('ABORT: libObj base mismatch — flag 绝对地址失效，需重新定位'); cam.setTerminalEnable(False); return
    BASE=base
    # 3) 校验 flag 槽当前值（应为0或上次残留）
    fp=rd512(cam,pid,FLAG_RT&~0xfff)
    log('flag@0x%x current=%s'%(FLAG_RT,fp[FLAG_RT&0xfff:FLAG_RT&0xfff+4].hex()))
    # 4) 曝光 flag 注入
    hp=bytearray(DUMP[EXP_HOOK_FILE&~0xfff:(EXP_HOOK_FILE&~0xfff)+0x1000]); hoff=EXP_HOOK_FILE&0xfff
    if hp[hoff:hoff+4]!=bytes.fromhex('2de9f04f'):
        log('ABORT dispC prologue=%s'%hp[hoff:hoff+4].hex()); cam.setTerminalEnable(False); return
    cp=bytearray(DUMP[EXP_CAVE_FILE&~0xfff:(EXP_CAVE_FILE&~0xfff)+0x1000]); coff=EXP_CAVE_FILE&0xfff
    cp[coff:coff+len(EXP_STUB)]=EXP_STUB; hp[hoff:hoff+4]=EXP_HOOK
    wr(cam,pid,(BASE+EXP_CAVE_FILE)&~0xfff,bytes(cp))
    wr(cam,pid,(BASE+EXP_HOOK_FILE)&~0xfff,bytes(hp))
    # 5) worker 注入
    hp2=bytearray(DUMP[WK_HOOK_FILE&~0xfff:(WK_HOOK_FILE&~0xfff)+0x1000]); hoff2=WK_HOOK_FILE&0xfff
    if hp2[hoff2:hoff2+4]!=bytes.fromhex('b0b50446'):
        log('ABORT worker prologue=%s'%hp2[hoff2:hoff2+4].hex()); cam.setTerminalEnable(False); return
    cp2=bytearray(DUMP[WK_CAVE_FILE&~0xfff:(WK_CAVE_FILE&~0xfff)+0x1000]); coff2=WK_CAVE_FILE&0xfff
    cp2[coff2:coff2+len(WK_STUB)]=WK_STUB; hp2[hoff2:hoff2+4]=WK_HOOK
    wr(cam,pid,(BASE+WK_CAVE_FILE)&~0xfff,bytes(cp2))
    wr(cam,pid,(BASE+WK_HOOK_FILE)&~0xfff,bytes(hp2))
    # 6) 读回校验
    v1=rd512(cam,pid,(BASE+EXP_HOOK_FILE)&~0xfff); v2=rd512(cam,pid,(BASE+WK_HOOK_FILE)&~0xfff)
    ok1=v1[hoff:hoff+4]==EXP_HOOK; ok2=v2[hoff2:hoff2+4]==WK_HOOK
    log('INJECT M1 exposure_ok=%s worker_ok=%s'%(ok1,ok2))
    log('stub-exposure=%dB stub-worker=%dB(soundId=4)'%(len(EXP_STUB),len(WK_STUB)))
    cam.setTerminalEnable(False)

if not R.wait_msc():
    log('ABORT not MSC')
else:
    try: senserShellCommand(complete=work)
    except Exception as e: log('err %r'%e)
    log('CLOSED — 若 ok=True：静音模式电子快门试拍（勿拔电池，RAM补丁拔电池即失）')
