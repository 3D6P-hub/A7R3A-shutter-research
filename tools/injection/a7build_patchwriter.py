from keystone import *
import struct
SRC=r'E:\Agent\a7r3a-research\ref-bionzx\ZVE10-Astra-Public-main\tools\flash\camtool\payload\patch_writer.s'
lines=open(SRC,encoding='utf-8').read().split('\n')
code=[]
for l in lines:
    s=l.split('@')[0].strip()
    if not s: continue
    if s.startswith('.'): continue
    code.append(s)
asm='\n'.join(code)
ks=Ks(KS_ARCH_ARM,KS_MODE_ARM)
enc,_=ks.asm(asm,0x10054)
code=bytes(enc)
print('code %d bytes'%len(code))
# minimal ELF32 ARM static exec
BASE=0x10000; hdr=52+32; entry=BASE+hdr
filesz=hdr+len(code)
eh=struct.pack('<16sHHIIIIIHHHHHH',
    b'\x7fELF\x01\x01\x01\x00'+b'\x00'*8,
    2,40,1,entry,52,0,0x5000002,52,32,1,0,0,0)
ph=struct.pack('<IIIIIIII',1,0,BASE,BASE,filesz,filesz,5,0x10000)
elf=eh+ph+code
out=r'E:\Agent\a7r3a-research\patch_writer'
open(out,'wb').write(elf)
print('patch_writer ELF %d bytes, entry=0x%x'%(len(elf),entry))
