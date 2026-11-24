# -*- coding: utf-8 -*-
"""Unicorn实证：仿真libObj .init_array全部初始化函数，记录开机执行足迹。
   守则v1.1 15.1：动态验证开机路径，而非仅静态零引用。"""
import struct, json
from unicorn import *
from unicorn.arm_const import *
P=r'E:\Agent\a7r3a-research\n15_extracted\lib\libObj.so'
data=open(P,'rb').read()
BASE=0x05dca000
RX_SZ=0x11a50e4
PLT_S=0xfc450; PLT_E=0x104070
TEXT_S=0x104070; TEXT_E=0xcf443c
ia_off=0x11a50e4; ia_sz=0x434
arr=struct.unpack('<%dI'%(ia_sz//4), data[ia_off:ia_off+ia_sz])
STOP=0xdead0000
executed=set()
mu=Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(BASE, 0x1300000, UC_PROT_ALL)  # 连续覆盖RX+数据段
mu.mem_write(BASE, data[:RX_SZ])
mu.mem_write(BASE+0x11a50e4, data[0x11a50e4:0x11a50e4+0xef710])
mu.mem_map(0x80000000, 0x100000, UC_PROT_ALL)  # stack
mu.mem_map(STOP&~0xfff, 0x1000, UC_PROT_ALL)
def hook_code(uc, addr, size, ud):
    off=addr-BASE
    if PLT_S<=off<PLT_E:   # 进PLT(import)=>停止该函数
        uc.emu_stop(); return
    if addr==STOP:
        uc.emu_stop(); return
    if TEXT_S<=off<TEXT_E:
        executed.add(off)
mu.hook_add(UC_HOOK_CODE, hook_code)
def run_func(va):
    mu.reg_write(UC_ARM_REG_SP, 0x80080000)
    mu.reg_write(UC_ARM_REG_LR, STOP|1)
    mu.reg_write(UC_ARM_REG_R0, 0)
    mu.reg_write(UC_ARM_REG_R1, 0)
    try:
        mu.emu_start(BASE+va, STOP, count=200000)
    except UcError:
        pass
ok=0
for k,va in enumerate(arr):
    fn=va&~1
    if not (TEXT_S<=fn<TEXT_E): continue
    run_func(fn); ok+=1
print('仿真初始化函数 %d/%d 个'%(ok,len(arr)))
print('开机初始化执行到的 .text 字节数: %d'%len(executed))
# 检查TsOtOS_2_init是否被执行
ts=0x53cf5a
hit=any(ts<=e<ts+598 for e in executed)
print('TsOtOS_2_init(0x53cf5a)被init_array执行:',hit)
# 候选洞 vs 执行足迹
cands=json.load(open(r'E:\Agent\a7r3a-research\audit2\cave_candidates.json'))
print('=== 候选洞是否被初始化执行 ===')
safe=[]
for c in sorted(cands,key=lambda c:-c['len'])[:15]:
    va=c['va']; ln=c['len']
    touched=sum(1 for e in executed if va<=e<va+ln)
    tag='被执行%d字节(不安全)'%touched if touched else '★初始化未执行'
    if not touched: safe.append(c)
    print('VA=0x%x len=%d %s'%(va,ln,tag))
json.dump({'executed_count':len(executed),'safe_candidates':safe},
          open(r'E:\Agent\a7r3a-research\audit2\unicorn_init_result.json','w'))
print('初始化未执行的候选: %d 个'%len(safe))
