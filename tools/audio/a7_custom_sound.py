# -*- coding: utf-8 -*-
"""自定义快门声导入（M4）：WAV→24kHz→f0→同尺寸覆盖 kind8 宿主 bin（n15 裸写）。
   用法：
     python a7_custom_sound.py --wav mysound.wav [--gain 1.0] [--bit4 0]
     python a7_custom_sound.py --bin Dslr_Emnt_High_Shutter_Burst.bin [--gain 1.0] [--bit4 0]
   宿主默认 = kind8 当前指向的 Burst.bin (2880B @ n15 0x5cc1c00)。
   写后拔电池冷启动（AP 重新加载样本）→ 重连 → a7_M1_inject.py（soundId=8）。
"""
import sys, os, time, wave, argparse, subprocess
import numpy as np
sys.path.insert(0, r'E:\Agent\a7r3a-research')
sys.path.insert(0, r'E:\Agent\a7r3a-research\pmca-src\Sony-PMCA-RE-master')
sys.path.insert(0, r'E:\Agent\a7r3a-research\sounds_wav')
import a7restore as R
from pmca.commands.usb import senserShellCommand
from f0enc import encode, decode
DIR=r'E:\Agent\a7r3a-research'
PY=r'C:\Users\18793\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe'
SND=DIR+r'\n15_extracted\share\avsystemsound'
HOST_OFF=0x5cc1c00; HOST_SIZE=2880   # kind8 = Burst.bin
ap=argparse.ArgumentParser()
ap.add_argument('--wav'); ap.add_argument('--bin')
ap.add_argument('--gain',type=float,default=1.0)
ap.add_argument('--bit4',type=int,default=0)
ap.add_argument('--off',type=lambda x:int(x,0),default=HOST_OFF)
ap.add_argument('--size',type=int,default=HOST_SIZE)
a=ap.parse_args()

def load_wav_24k(path):
    w=wave.open(path,'rb')
    ch=w.getnchannels(); sw=w.getsampwidth(); fr=w.getframerate(); n=w.getnframes()
    raw=w.readframes(n); w.close()
    if sw==2: x=np.frombuffer(raw,dtype='<i2').astype(np.float64)
    elif sw==1: x=(np.frombuffer(raw,dtype=np.uint8).astype(np.float64)-128)*256
    elif sw==4: x=(np.frombuffer(raw,dtype='<i4').astype(np.float64)/65536)
    else: raise SystemExit('unsupported sample width %d'%sw)
    if ch==2: x=(x[0::2]+x[1::2])/2
    if fr!=24000:
        t=np.arange(len(x))/fr; t2=np.arange(int(len(x)*24000/fr))/24000
        x=np.interp(t2,t,x)
    return x

if a.wav:
    pcm=load_wav_24k(a.wav)
    print('WAV %s -> %d samples @24k (%.0f ms)'%(a.wav,len(pcm),len(pcm)/24))
elif a.bin:
    pcm=decode(open(os.path.join(SND,a.bin),'rb').read()).astype(np.float64)
    print('re-encode factory %s -> %d samples'%(a.bin,len(pcm)))
else:
    raise SystemExit('need --wav or --bin')

f0=encode(pcm, gain=a.gain, bit4=a.bit4)
# 同尺寸：截断或补零
if len(f0)>a.size: f0=f0[:a.size]
elif len(f0)<a.size: f0=f0+b'\x00'*(a.size-len(f0))
# 帧对齐（32B）
f0=f0[:a.size//32*32]
open(DIR+r'\custom-sound.bin','wb').write(f0)
print('f0 %dB (gain=%.2f bit4=%d) -> host n15 0x%x size=%d'%(len(f0),a.gain,a.bit4,a.off,a.size))

subprocess.run([PY, DIR+r'\a7build_patchwriter.py'],check=True,capture_output=True)
pw=open(DIR+r'\patch_writer','rb').read()
def work(cam):
    try: cam.dev.driver.backend.dev.default_timeout=20000
    except: pass
    cam.setTerminalEnable(False); time.sleep(1); cam.setTerminalEnable(True); time.sleep(2)
    R.term_exec(cam,'',wait=3)
    R.jwrite(cam,'/tmp/jiritsu/pw',pw); time.sleep(0.5)
    R.term_exec(cam,'chmod +x /tmp/jiritsu/pw',wait=6)
    R.jwrite(cam,'/tmp/jiritsu/p.bin',f0); time.sleep(0.3)
    R.term_exec(cam,'/tmp/jiritsu/pw /dev/nflasha15 0x%x /tmp/jiritsu/p.bin'%a.off,wait=12)
    R.term_exec(cam,'sync; echo SYNCED',wait=10); time.sleep(0.5)
    blk=a.off//512
    R.term_exec(cam,'dd if=/dev/nflasha15 of=/tmp/jiritsu/r.bin bs=512 skip=%d count=2 2>/dev/null'%blk,wait=12)
    time.sleep(0.4); d=R.jread_raw(cam,'/tmp/jiritsu/r.bin')
    got=d[a.off%512:a.off%512+32]
    print('readback first frame:', got.hex(), 'OK' if got==f0[:32] else 'MISMATCH')
    cam.setTerminalEnable(False)
if R.wait_msc(max_sec=60):
    try: senserShellCommand(complete=work)
    except Exception as e: print('err',repr(e))
print('done - 拔电池5秒 → 重连 → a7_M1_inject.py (soundId=8) → 试拍')
