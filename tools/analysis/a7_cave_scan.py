# -*- coding: utf-8 -*-
"""离线找安全洞区：RX段纯零填充候选 + 多路引用扫描 + init表定位。守则v1.1 2.2/15.2"""
import struct
from elftools.elf.elffile import ELFFile
P=r'E:\Agent\a7r3a-research\n15_extracted\lib\libObj.so'
f=open(P,'rb'); data=f.read(); f.seek(0)
elf=ELFFile(f)
print('=== ELF 段 ===')
rx=[]
for seg in elf.iter_segments():
    if seg.header.p_type=='PT_LOAD':
        fl=seg.header.p_flags
        x='X' if fl&1 else '-'
        print('LOAD off=0x%x vaddr=0x%x filesz=0x%x memsz=0x%x flags=%s%s'%(
            seg.header.p_offset,seg.header.p_vaddr,seg.header.p_filesz,seg.header.p_memsz,
            'R' if fl&4 else '-',x))
        if fl&1: rx.append((seg.header.p_offset,seg.header.p_filesz,seg.header.p_vaddr))
print('=== 节区(关键) ===')
for s in elf.iter_sections():
    if s.name in ('.init_array','.fini_array','.text','.rodata','.data.rel.ro','.init','.plt'):
        print('%s addr=0x%x off=0x%x size=0x%x'%(s.name,s.header.sh_addr,s.header.sh_offset,s.header.sh_size))
# TsOtOS_2_init 符号
print('=== TsOtOS 相关符号 ===')
for secname in ('.dynsym','.symtab'):
    sec=elf.get_section_by_name(secname)
    if sec:
        for sym in sec.iter_symbols():
            if 'TsOtOS' in sym.name or 'OS_2_init' in sym.name:
                print('%s: %s val=0x%x size=%d'%(secname,sym.name,sym.entry.st_value,sym.entry.st_size))
# RX段纯零填充区(>=128B)
print('=== RX段纯零填充候选(>=128B) ===')
cands=[]
for off,sz,va in rx:
    seg=data[off:off+sz]
    i=0; n=len(seg)
    while i<n:
        if seg[i]==0:
            j=i
            while j<n and seg[j]==0: j+=1
            run=j-i
            if run>=128:
                cands.append((off+i,va+i,run))
            i=j
        else: i+=1
for fo,vaddr,run in cands[:40]:
    print('fileoff=0x%x VA=0x%x len=%d'%(fo,vaddr,run))
print('共 %d 个>=128B零区'%len(cands))
import json
json.dump([{'fileoff':fo,'va':va,'len':r} for fo,va,r in cands],
          open(r'E:\Agent\a7r3a-research\audit2\cave_candidates.json','w'))
