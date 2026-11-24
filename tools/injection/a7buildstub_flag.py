from keystone import *
ks=Ks(KS_ARCH_ARM,KS_MODE_THUMB)
CAVE=0x53cf5a
FLAG=0x070a47f8
asm='''
push {r0,r1,r2,r3,lr}
ldr r1, [r0, #0x1c]
cbz r1, skip
ldrb r2, [r1]
cmp r2, #4
bne skip
ldrh r2, [r1, #2]
movw r3, #0x1000
cmp r2, r3
beq cm
movw r3, #0x1001
cmp r2, r3
bne skip
cm:
ldr r2, [r1, #8]
movw r3, #0xf000
cmp r2, r3
bne skip
movw r0, #0x47f8
movt r0, #0x070a
movs r1, #1
str r1, [r0]
skip:
pop {r0,r1,r2,r3,lr}
push.w {r4,r5,r6,r7,r8,r9,r10,r11,lr}
b.w 0xa36290
'''
enc,_=ks.asm(asm,CAVE); stub=bytes(enc)
open(r'E:\Agent\a7r3a-research\stub-exposure.bin','wb').write(stub)
h,_=ks.asm('b.w 0x%x'%CAVE,0xa3628c)
open(r'E:\Agent\a7r3a-research\hook-exposure.bin','wb').write(bytes(h))
print('FLAG-WRITE stub %d bytes (writes 1 to 0x%x, no MWF), hook=%s'%(len(stub),FLAG,bytes(h).hex()))
