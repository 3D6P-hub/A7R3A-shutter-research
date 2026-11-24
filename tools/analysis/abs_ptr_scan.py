import struct, io
PATH = r"E:\Agent\a7r3a-research\n15_extracted\lib\libObj.so"
data = open(PATH, "rb").read()
handlers = {0xa0d824:"dispB",0xa3628c:"dispC",0xabbbe4:"dispE",0xac5418:"dispF",
            0xa357ec:"evt3018",0xa9467c:"evt-marker",0xc1f76c:"evt3000",
            0x2a6ed0:"ReqStart",0x29b2d0:"ExecCmdStartSysSnd"}
out = io.StringIO()
def p(*a): print(*a, file=out)
for H,name in handlers.items():
    for val,tag in [(H,"abs"),(H|1,"thumb")]:
        needle = struct.pack('<I', val)
        locs=[]; s=0
        while True:
            i=data.find(needle,s)
            if i<0: break
            locs.append(i); s=i+1
            if len(locs)>40: break
        p("%s 0x%x (%s): %d hits %s" % (name,H,tag,len(locs), " ".join("0x%x"%x for x in locs[:20])))
        for L in locs[:6]:
            p("   @0x%x ctx=%s" % (L, data[max(0,L-16):L+20].hex(' ')))
open(r"E:\Agent\a7r3a-research\abs-ptr-scan.txt",'w',encoding='utf-8').write(out.getvalue())
print(out.getvalue())
