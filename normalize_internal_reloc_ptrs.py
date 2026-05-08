#!/usr/bin/env python3
"""
Normalize internal relocated pointers in a raw unpacked libdp image.

For IDA base 0 analysis, runtime pointers like:
  0x73e4ec51c0
become file/image offsets:
  0x891c0

External import GOT entries outside [load_bias, load_bias+image_size) are kept.
"""
from pathlib import Path
import sys

DEFAULT_BIAS = 0x73e4e3c000
DEFAULT_SIZE = 0x90000

def u64(b, off): return int.from_bytes(b[off:off+8], 'little')
def p64(b, off, v): b[off:off+8] = int(v).to_bytes(8, 'little')

def main():
    if len(sys.argv) not in (3, 5):
        print(f"Usage: {sys.argv[0]} <in.bin> <out.bin> [load_bias_hex image_size_hex]")
        sys.exit(1)
    inp = Path(sys.argv[1])
    outp = Path(sys.argv[2])
    bias = int(sys.argv[3], 16) if len(sys.argv) == 5 else DEFAULT_BIAS
    size = int(sys.argv[4], 16) if len(sys.argv) == 5 else DEFAULT_SIZE

    b = bytearray(inp.read_bytes())
    lo, hi = bias, bias + size
    patched = []

    for off in range(0, len(b) - 7, 8):
        v = u64(b, off)
        if lo <= v < hi:
            nv = v - bias
            p64(b, off, nv)
            patched.append((off, v, nv))

    outp.write_bytes(b)
    print(f"input  : {inp}")
    print(f"output : {outp}")
    print(f"bias   : {bias:#x}")
    print(f"range  : [{lo:#x}, {hi:#x})")
    print(f"patched: {len(patched)} qwords")
    for off, v, nv in patched[:80]:
        print(f"  file+{off:#x}: {v:#x} -> {nv:#x}")
    if len(patched) > 80:
        print(f"  ... {len(patched)-80} more")

if __name__ == '__main__':
    main()
