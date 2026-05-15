#!/usr/bin/env python3
import re, sys
from pathlib import Path
from collections import Counter, defaultdict

DP=Path('dumps/ic_dat_dumps/dp_mp3_decompressed.bin').read_bytes()
class_count=int.from_bytes(DP[0x20:0x24],'little')
entry_count=int.from_bytes(DP[0x24:0x28],'little')
entry_base=0x28
class_off_base=entry_base+16*entry_count
first=class_off_base+4*class_count
string_base=DP.index(0, first)+1

def s(rel):
    off=string_base+rel
    end=DP.find(b'\0',off)
    return DP[off:end].decode('utf-8','replace')
def signed32(x):
    x &= 0xffffffff
    return x-0x100000000 if x&0x80000000 else x
def mask(op):
    x=signed32(op)
    if x<=-9: return x & 0xffff
    if x>=0: return x & 0xffffffff
    return x & 0xf
def entry(op):
    idx=mask(op)
    if idx>=entry_count: return None
    off=entry_base+idx*16
    raw=DP[off:off+16]
    w0,n,sig,extra=[int.from_bytes(raw[i:i+4],'little') for i in range(0,16,4)]
    ci=w0>>10; cr=int.from_bytes(DP[class_off_base+4*ci:class_off_base+4*ci+4],'little')
    return dict(idx=idx,kind=(w0>>5)&31,flags=w0&31,cls=s(cr),name=s(n),sig=s(sig),extra=s(extra),w0=w0)

const_re=re.compile(r'^\s*const(?:/4|/16|/high16)?\s+([vp]\d+),\s+(-?0x[0-9a-fA-F]+|-?\d+)')
const_wide_re=re.compile(r'^\s*const(?:-wide)?(?:/16|/32|/high16)?\s+([vp]\d+),\s+(-?0x[0-9a-fA-F]+|-?\d+)')
invoke_re=re.compile(r'^\s*invoke-static(?:/range)?\s+\{([^}]+)\},\s+Lcom/dexprotector/detector/envchecks/LibApplication;->i\(([^)]*)\)(\S+)')

def parse_regs(s):
    s=s.strip()
    if '..' in s:
        a,b=[x.strip() for x in s.split('..')]
        pref=a[0]
        ia=int(a[1:]); ib=int(b[1:])
        return [f'{pref}{i}' for i in range(ia,ib+1)]
    return [x.strip() for x in s.split(',') if x.strip()]

cnt=Counter(); examples={}; total=0; resolved=0; bad=0
ret_cnt=Counter(); sigs=Counter(); unsupported=[]
for path in Path('build/classes0_smali').rglob('*.smali'):
    lines=path.read_text(errors='replace').splitlines()
    last_const={}
    for i,line in enumerate(lines):
        m=const_re.match(line) or const_wide_re.match(line)
        if m:
            try: last_const[m.group(1)]=int(m.group(2),0)
            except: pass
        inv=invoke_re.match(line)
        if inv:
            total+=1
            regs=parse_regs(inv.group(1)); proto=inv.group(2); ret=inv.group(3)
            op=last_const.get(regs[0]) if regs else None
            if op is None:
                bad+=1; continue
            e=entry(op)
            if not e: bad+=1; continue
            resolved+=1
            key=(ret,e['kind'],e['flags'],e['name'] if e['name'].startswith('<') else '')
            cnt[(ret,e['kind'],e['flags'])]+=1
            ret_cnt[ret]+=1
            sigs[(proto,ret,e['extra'])]+=1
            examples.setdefault((ret,e['kind'],e['flags']), (path, i+1, op, e, line.strip()))
print('total',total,'resolved',resolved,'bad',bad)
print('top ret',ret_cnt.most_common(20))
print('\nkind/flags by ret:')
for (ret,kind,flags),n in cnt.most_common(80):
    p,ln,op,e,line=examples[(ret,kind,flags)]
    print(f'{n:6} ret={ret:22} kind={kind:2} flags={flags:2} op={op} {hex(op&0xffffffff)} {e["cls"]}->{e["name"]}{e["sig"]} extra={e["extra"]} @ {p}:{ln}')
