#!/usr/bin/env python3
"""
Parse DexProtector dp.mp3 dispatcher table.

Known layout for this sample's decompressed dp.mp3:
  u32 @0x20 = class_count
  u32 @0x24 = dispatch_entry_count
  entries   = 0x28, 16 bytes each
  class_off = entries + dispatch_entry_count * 16, u32[class_count]
  first string at class_off + class_count*4 is dispatcher class name
  string_pool = after that first NUL; all offsets in entries/class_off are relative to string_pool

Opcode index masking follows the hidden wrapper:
  if opcode >= 0: index = opcode
  elif opcode <= -9: index = opcode & 0xffff
  else: index = opcode & 0xf
"""
import argparse
from pathlib import Path

RET_BASE = {
    'Z': 3,   # boolean
    'B': 11,  # byte
    'S': 19,  # short
    'C': 27,  # char
    'I': 35,  # int
    'J': 43,  # long
    'F': 51,  # float
    'D': 59,  # double
    'L': 67,  # object/array
    'V': 78,  # void
}

# Only mappings we have confirmed in this target so far.
KNOWN = {
    ('I', 7): 'GetIntField / read int instance field',
    ('L', 6): 'GetObjectField / read object instance field (inferred from String field reads)',
    ('V', 15): 'SetObjectField / write object instance field (inferred from String field writes)',
    ('V', 20): 'SetIntField / write int instance field (inferred from int field writes)',
    ('V', 0): 'CallVoidMethod-like instance call (verify with JNI trace per opcode)',
}

def parse_int(s: str) -> int:
    return int(s, 0)

def signed32(x: int) -> int:
    x &= 0xffffffff
    return x - 0x100000000 if x & 0x80000000 else x

def opcode_to_index(op: int) -> int:
    s = signed32(op)
    if s <= -9:
        return s & 0xffff
    if s >= 0:
        return s & 0xffffffff
    return s & 0xf

def cstr(buf: bytes, off: int) -> str:
    if off < 0 or off >= len(buf):
        return f'<bad_off {off:#x}>'
    end = buf.find(b'\0', off)
    if end < 0:
        end = min(len(buf), off + 256)
    return buf[off:end].decode('utf-8', 'replace')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('opcodes', nargs='+', type=parse_int, help='opcode(s), decimal or hex; negative ok')
    ap.add_argument('-f', '--file', default='dumps/ic_dat_dumps/dp_mp3_decompressed.bin')
    ap.add_argument('-r', '--ret', default=None, help='optional shorty return type: I/L/V/Z/B/S/C/J/F/D')
    args = ap.parse_args()

    data = Path(args.file).read_bytes()
    class_count = int.from_bytes(data[0x20:0x24], 'little')
    entry_count = int.from_bytes(data[0x24:0x28], 'little')
    entry_base = 0x28
    class_off_base = entry_base + 16 * entry_count
    first_string = class_off_base + 4 * class_count
    nul = data.index(0, first_string)
    dispatcher_class = data[first_string:nul].decode('utf-8', 'replace')
    string_base = nul + 1

    print(f'file={args.file}')
    print(f'class_count=0x{class_count:x} entry_count=0x{entry_count:x}')
    print(f'entry_base=0x{entry_base:x} class_off_base=0x{class_off_base:x} string_base=0x{string_base:x}')
    print(f'dispatcher_class="{dispatcher_class}"')

    ret = args.ret.upper() if args.ret else None
    for op in args.opcodes:
        idx = opcode_to_index(op)
        print('\n---')
        print(f'opcode={op} ({op & 0xffffffff:#x}) signed32={signed32(op)} -> table_index={idx:#x} ({idx})')
        if idx >= entry_count:
            print('OUT_OF_RANGE')
            continue
        off = entry_base + idx * 16
        raw = data[off:off+16]
        w0, name_rel, sig_rel, extra_rel = [int.from_bytes(raw[i:i+4], 'little') for i in range(0, 16, 4)]
        flags = w0 & 0x1f
        kind = (w0 >> 5) & 0x1f
        class_idx = w0 >> 10
        class_rel = int.from_bytes(data[class_off_base + class_idx*4:class_off_base + class_idx*4 + 4], 'little')
        print(f'entry_off=0x{off:x} raw={raw.hex()}')
        print(f'w0={w0:#x} flags={flags} kind={kind} class_idx={class_idx}')
        print(f'class="{cstr(data, string_base + class_rel)}"  rel={class_rel:#x}')
        print(f'name ="{cstr(data, string_base + name_rel)}"  rel={name_rel:#x}')
        print(f'sig  ="{cstr(data, string_base + sig_rel)}"  rel={sig_rel:#x}')
        print(f'extra="{cstr(data, string_base + extra_rel)}"  rel={extra_rel:#x}')
        if ret:
            base = RET_BASE.get(ret)
            if base is None:
                print(f'ret={ret}: unknown return type')
            else:
                slot = base + kind
                desc = KNOWN.get((ret, kind), 'handler not named yet; use JNI trace to identify exact JNIEnv call')
                print(f'ret={ret}: wrapper_base={base} handler_slot={slot} -> {desc}')

if __name__ == '__main__':
    main()
