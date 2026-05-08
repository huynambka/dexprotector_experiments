#!/usr/bin/env python3
"""
Build a hybrid unpacked image for IDA:
- start from a post-relocation dump, so GOT/data pointers are relocated;
- restore dynamic/symbol/string/relocation/init/fini metadata from the original pre-reloc dump,
  because sub_167C wipes some of those tables.

Usage:
  python3 merge_relocated_with_metadata.py \
    dumps/unpacked_image_0x90000.bin \
    dumps/after_sub167c_full_reloc_image_0x90000.bin \
    dumps/unpacked_image_relocated_hybrid.bin
"""
from pathlib import Path
import sys

DYN_DEFAULT = 0x84960

def u64(b, off): return int.from_bytes(b[off:off+8], 'little')
def p64(b, off, v): b[off:off+8] = int(v).to_bytes(8, 'little')

def parse_dyn(b, dyn=DYN_DEFAULT, max_entries=128):
    out=[]
    for i in range(max_entries):
        off = dyn + i*16
        tag = u64(b, off)
        val = u64(b, off+8)
        out.append((tag, val, off))
        if tag == 0:
            break
    return out

def first(dyn, tag, default=0):
    for t,v,_ in dyn:
        if t == tag: return v
    return default

def copy_range(dst, src, start, size, name):
    if not start or not size:
        return
    end = start + size
    if end > len(src) or end > len(dst):
        print(f'[skip] {name}: {start:#x}+{size:#x} outside image')
        return
    dst[start:end] = src[start:end]
    print(f'[restore] {name}: {start:#x}-{end:#x} size={size:#x}')


def main():
    if len(sys.argv) != 4:
        print(__doc__.strip())
        sys.exit(1)
    orig_path, reloc_path, out_path = map(Path, sys.argv[1:])
    orig = bytearray(orig_path.read_bytes())
    reloc = bytearray(reloc_path.read_bytes())
    if len(orig) != len(reloc):
        raise SystemExit(f'size mismatch: orig={len(orig):#x} reloc={len(reloc):#x}')

    out = bytearray(reloc)
    dyn = parse_dyn(orig)
    dyn_end = dyn[-1][2] + 16

    symtab = first(dyn, 6)
    strtab = first(dyn, 5)
    strsz  = first(dyn, 10)
    if symtab and strtab and strsz and strtab >= symtab:
        copy_range(out, orig, symtab, (strtab + strsz) - symtab, 'symtab..strtab')

    rela = first(dyn, 7); relasz = first(dyn, 8)
    copy_range(out, orig, rela, relasz, 'DT_RELA')

    jmprel = first(dyn, 23); pltrelsz = first(dyn, 2)
    copy_range(out, orig, jmprel, pltrelsz, 'DT_JMPREL')

    relr = first(dyn, 36); relrsz = first(dyn, 35)
    copy_range(out, orig, relr, relrsz, 'DT_RELR')

    init = first(dyn, 25); initsz = first(dyn, 27)
    copy_range(out, orig, init, initsz, 'DT_INIT_ARRAY')

    fini = first(dyn, 26); finisz = first(dyn, 28)
    copy_range(out, orig, fini, finisz, 'DT_FINI_ARRAY')

    copy_range(out, orig, DYN_DEFAULT, dyn_end - DYN_DEFAULT, 'DYNAMIC')

    Path(out_path).write_bytes(out)
    print(f'[done] wrote {out_path} size={len(out):#x}')

if __name__ == '__main__':
    main()
