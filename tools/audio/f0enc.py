# -*- coding: utf-8 -*-
"""A7R3A f0 编码器（参照 A7M4 convert.c block()，适配 A7R3A shift<=8）。
   f0 帧 = 32B：byte0=shift指数(0..8)，bytes1..31=int8量化（sample = q << shift）。
   音量 = 编码前对 PCM 乘 gain（A7M4 式，幅度即音量）。
   提供 encode(pcm_int16, gain) 与 decode(bytes)；round-trip 验证。
"""
import numpy as np

def decode(data):
    B=np.frombuffer(data,dtype=np.uint8).reshape(-1,32)
    shift=(B[:,0]&0x0F).astype(np.int32)
    q=B[:,1:].astype(np.int8).astype(np.int32)
    return (q<<shift[:,None]).flatten().astype(np.int16)

def encode(pcm, gain=1.0, max_shift=8, bit4=0):
    pcm=np.asarray(pcm,dtype=np.float64)*gain
    n=len(pcm); blocks=(n+30)//31
    out=np.zeros(blocks*32,dtype=np.uint8)
    for b in range(blocks):
        seg=pcm[b*31:(b+1)*31]
        count=len(seg)
        peak=int(np.max(np.abs(seg))) if count else 0
        shift=0
        while shift<max_shift and peak>(127<<shift): shift+=1
        out[b*32]=shift|(bit4<<4)
        for i in range(31):
            v=int(round(seg[i])) if i<count else 0
            a=abs(v)
            q=(a+(1<<(shift-1) if shift else 0))>>shift
            if v>=0 and q>127: q=127
            if v<0 and q>128: q=128
            out[b*32+i+1]=np.uint8(np.int8(-q if v<0 else q))
    return out.tobytes()

if __name__=='__main__':
    import os
    D=r'E:\Agent\a7r3a-research\n15_extracted\share\avsystemsound'
    for nm in ['Dslr_Emnt_High_10FPS_Kasha.bin','Dslr_Emnt_High_Shutter_Burst.bin','Dslr_Emnt_High_Shutter_Ka.bin']:
        orig=open(os.path.join(D,nm),'rb').read()
        pcm=decode(orig)
        re=encode(pcm, gain=1.0)
        pcm2=decode(re)
        # 比较解码后 PCM（容许量化误差）
        err=np.abs(pcm.astype(int)-pcm2.astype(int))
        print('%s: orig=%dB re=%dB  PCM max_err=%d mean_err=%.2f  peak_orig=%d peak_re=%d'%(
            nm,len(orig),len(re),err.max(),err.mean(),np.abs(pcm).max(),np.abs(pcm2).max()))
