# -*- coding: utf-8 -*-
"""定位TsOtOS_2_init的调用表(根因) + 候选洞多路引用扫描。守则2.2"""
import struct, json
P=r'E:\Agent\a7r3a-research\n15_extracted\lib\libObj.so'
data=open(P,'rb').read()
TARGET=0x53cf5b  # TsOtOS_2_init Thumb
print('=== 搜索指向 TsOtOS_2_init(0x53cf5b/0x53cf5a) 的指针 ===')
for val in (0x53cf5b,0x53cf5a,0x53cf59):
    needle=struct.pack('<I',val)
    idx=0; hits=[]
    while True:
        i=data.find(needle,idx)
        if i<0: break
        hits.append(i); idx=i+1
    print('ptr 0x%x 出现在文件偏移: %s'%(val,[hex(h) for h in hits[:20]]))
# .init_array 内容
ia_off=0x11a50e4; ia_sz=0x434
print('=== .init_array (前40项) ===')
arr=struct.unpack('<%dI'%(ia_sz//4), data[ia_off:ia_off+ia_sz])
for k,v in enumerate(arr[:40]):
    mark=' <== TsOtOS_2_init!' if v in (0x53cf5b,0x53cf5a) else ''
    print('[%d] 0x%x%s'%(k,v,mark))
print('init_array含TsOtOS_2_init:', any(v in (0x53cf5b,0x53cf5a) for v in arr))
# 候选洞引用扫描
cands=json.load(open(r'E:\Agent\a7r3a-research\audit2\cave_candidates.json'))
# 选最大的几个
big=sorted(cands,key=lambda c:-c['len'])[:8]
print('=== 最大8个候选洞的多路引用扫描 ===')
for c in big:
    va=c['va']; ln=c['len']; fo=c['fileoff']
    # 绝对指针引用(数据段中指向该洞的指针)
    ptr_refs=[]
    for off in range(va,va+ln,4):
        needle=struct.pack('<I',off)
        i=data.find(needle)
        # 排除洞自身
        while i>=0 and fo<=i<fo+ln:
            i=data.find(needle,i+1)
        if i>=0: ptr_refs.append((hex(off),hex(i)))
    # Thumb地址右移形式(指针|1)
    thumb_refs=[]
    for off in range(va,va+min(ln,64),2):
        needle=struct.pack('<I',off|1)
        i=data.find(needle)
        while i>=0 and fo<=i<fo+ln:
            i=data.find(needle,i+1)
        if i>=0: thumb_refs.append((hex(off),hex(i)))
    print('洞 VA=0x%x len=%d: 绝对指针引用=%d %s Thumb引用=%d %s'%(
        va,ln,len(ptr_refs),ptr_refs[:3],len(thumb_refs),thumb_refs[:3]))
