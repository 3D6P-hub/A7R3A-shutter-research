# -*- coding: utf-8 -*-
# 参数化 worker stub：python a7buildstub_worker_sid.py <soundId>
#   soundId=4   → kind4 (FORCUSLOCK)
#   soundId=0x37(55) → KASHA_CONTINUOUS 行（kind8 方案改 kindId=8 后 → kind8）
#   soundId=8   → 直接 kind8（备用，若 AP 把值当 kindId 用）
# PLT 全 blx；曝光侧用 a7buildstub_flag.py。产物 stub-worker.bin / hook-worker.bin。
import sys
from keystone import *
SOUNDID=int(sys.argv[1],0) if len(sys.argv)>1 else 4
ks=Ks(KS_ARCH_ARM,KS_MODE_THUMB)
CAVE=0x53d000
asm='''
push {r0,r1,r2,r3,lr}
movw r0, #0x47f8
movt r0, #0x070a
ldr r1, [r0]
cmp r1, #1
bne skip
movs r1, #0
str r1, [r0]
bl kasha_sub
skip:
pop {r0,r1,r2,r3,lr}
push {r4,r5,r7,lr}
mov r4, r0
b 0x82c5f0
kasha_sub:
push {r0,r1,r2,r3,r4,r5,r6,r7,lr}
sub sp, #0x80
add r7, sp, #0x10
add r0, r7, #0x1c
movw r1, #0x3410
mov.w r2, #0x1120
blx 0xff7b8
add r0, r7, #0x14
movs r1, #SOUNDID
blx 0x102b34
add r0, r7, #0xc
movs r1, #0
blx 0x102b34
adds r0, r7, #4
movs r1, #0
blx 0x102b34
add r0, r7, #0x1c
mov.w r1, #0x1000
add r2, r7, #0x14
blx 0x1027e4
add r0, r7, #0x1c
movw r1, #0x1001
add r2, r7, #0xc
blx 0x1027e4
add r0, r7, #0x1c
movw r1, #0x1002
adds r2, r7, #4
blx 0x1027e4
movs r0, #7
bl 0x34d840
mov r5, r0
cbz r0, kcleanup
mov r0, r5
add r1, r7, #0x1c
blx 0xfd2a0
kcleanup:
adds r0, r7, #4
blx 0xfd2f4
add r0, r7, #0xc
blx 0xfd2f4
add r0, r7, #0x14
blx 0xfd2f4
add r0, r7, #0x1c
blx 0xfefcc
add sp, #0x80
pop {r0,r1,r2,r3,r4,r5,r6,r7,lr}
bx lr
'''.replace('#SOUNDID','#%d'%SOUNDID)
enc,_=ks.asm(asm,CAVE); stub=bytes(enc)
open(r'E:\Agent\a7r3a-research\stub-worker.bin','wb').write(stub)
h,_=ks.asm('b.w 0x%x'%CAVE,0x82c5ec)
open(r'E:\Agent\a7r3a-research\hook-worker.bin','wb').write(bytes(h))
print('WORKER soundId=%d(0x%x) stub %dB hook=%s'%(SOUNDID,SOUNDID,len(stub),bytes(h).hex()))
