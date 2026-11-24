# -*- coding: utf-8 -*-
"""细扫.text代码区零隙(>=64B) + 仅数据段引用判定 + dlsym字符串确认"""
import struct, json
P=r'E:\Agent\a7r3a-research\n15_extracted\lib\libObj.so'
data=open(P,'rb').read()
# dlsym 字符串确认
s=data.find(b'TsOtOS_2_init\x00')
print('字符串 TsOtOS_2_init 文件偏移:',hex(s) if s>=0 else '无')
# .text 范围
TEXT_S=0x104070; TEXT_E=0x104070+0xbf03cc
# 数据段范围(引用判定只算这些段的指针,排除.text指令字节误报)
DATA_SEGS=[(0xcf4448,0xcf4448+0x34b606),(0x11a50e4,0x11a50e4+0xef710)]  # rodata + R-段
def in_data(i):
    return any(a<=i<b for a,b in DATA_SEGS)
# .text 零隙 >=64
print('=== .text代码区零隙(>=64B) + 数据段引用 ===')
seg=data[TEXT_S:TEXT_E]
i=0;n=len(seg);cands=[]
while i<n:
    if seg[i]==0:
        j=i
        while j<n and seg[j]==0: j+=1
        if j-i>=64:
            va=TEXT_S+i; ln=j-i
            # 数据段中指向洞内地址的指针
            refs=0; ex=[]
            for off in range(va&~3, va+ln, 4):
                needle=struct.pack('<I',off)
                k=data.find(needle)
                while k>=0:
                    if in_data(k) and not (TEXT_S+i<=k<TEXT_S+j):
                        refs+=1
                        if len(ex)<3: ex.append(hex(k))
                        break
                    k=data.find(needle,k+1)
            cands.append((va,ln,refs,ex))
        i=j
    else: i+=1
for va,ln,refs,ex in sorted(cands,key=lambda c:-c[1])[:25]:
    tag='★无数据引用' if refs==0 else '有%d引用'%refs
    print('VA=0x%x len=%d %s %s'%(va,ln,tag,ex))
print('共%d个.text零隙; 无数据引用的:%d'%(len(cands),sum(1 for c in cands if c[2]==0)))
json.dump([{'va':va,'len':ln,'datarefs':r} for va,ln,r,_ in cands],
          open(r'E:\Agent\a7r3a-research\audit2\text_caves.json','w'))
