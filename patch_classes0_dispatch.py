#!/usr/bin/env python3
"""
Patch DexProtector LibApplication.i(...) dispatcher calls in a baksmali tree using
assets/dp.mp3 decrypted dispatcher map.

This is intentionally conservative: supported direct replacements are emitted,
unsupported/unresolved calls are left unchanged. Targeted first at classes0.

Usage:
  python3 patch_classes0_dispatch.py \
    --in build/classes0_smali \
    --out build/classes0_smali_patched \
    --dp dumps/ic_dat_dumps/dp_mp3_decompressed.bin
"""
import argparse, os, re, shutil
from pathlib import Path
from collections import Counter, defaultdict

LIBAPP_OWNER = 'Lcom/dexprotector/detector/envchecks/LibApplication;'
INVOKE_RE = re.compile(r'^(?P<indent>\s*)invoke-static(?P<range>/range)?\s+\{(?P<regs>[^}]*)\},\s+Lcom/dexprotector/detector/envchecks/LibApplication;->i\((?P<proto>[^)]*)\)(?P<ret>\S+)')
CONST_RE = re.compile(r'^\s*const(?:/4|/16|/high16)?\s+(?P<reg>[vp]\d+),\s+(?P<val>-?0x[0-9a-fA-F]+|-?\d+)')
CONST_WIDE_RE = re.compile(r'^\s*const-wide(?:/16|/32|/high16)?\s+(?P<reg>[vp]\d+),\s+(?P<val>-?0x[0-9a-fA-F]+|-?\d+)')
MOVE_INT_RE = re.compile(r'^\s*move(?:/from16|/16)?\s+(?P<dst>[vp]\d+),\s+(?P<src>[vp]\d+)')
MOVE_RESULT_RE = re.compile(r'^(?P<indent>\s*)move-result(?P<suffix>(?:-object|-wide)?)\s+(?P<dst>[vp]\d+)')
CLASS_RE = re.compile(r'^\.class\s+.*\s+(L[^;]+;)')
INTERFACE_RE = re.compile(r'^\.class\s+.*\binterface\b')
METHOD_RE = re.compile(r'^\.method\s+(?P<decl>.*?)(?P<name>[^\s(]+)\((?P<params>[^)]*)\)(?P<ret>\S+)')
REGISTERS_RE = re.compile(r'^\s*\.registers\s+(?P<n>\d+)')

KNOWN_INTERFACES = {
    'Ljava/lang/Iterable;', 'Ljava/lang/CharSequence;', 'Ljava/lang/Comparable;',
    'Ljava/lang/Runnable;', 'Ljava/lang/AutoCloseable;', 'Ljava/io/Closeable;',
    'Ljava/util/Collection;', 'Ljava/util/List;', 'Ljava/util/Set;', 'Ljava/util/Map;',
    'Ljava/util/Map$Entry;', 'Ljava/util/Iterator;', 'Ljava/util/ListIterator;',
    'Ljava/util/concurrent/Callable;', 'Ljava/util/concurrent/Future;',
    'Ljava/util/concurrent/locks/Condition;', 'Ljava/util/concurrent/locks/Lock;',
    'Ljava/nio/file/Path;',
}

def signed32(x):
    x &= 0xffffffff
    return x - 0x100000000 if x & 0x80000000 else x

def opcode_to_index(op):
    s = signed32(op)
    if s <= -9:
        return s & 0xffff
    if s >= 0:
        return s & 0xffffffff
    return s & 0xf

def cstr(buf, off):
    if off < 0 or off >= len(buf):
        return f'<bad_off_{off:x}>'
    end = buf.find(b'\0', off)
    if end < 0:
        end = min(len(buf), off + 256)
    return buf[off:end].decode('utf-8', 'replace')

class DpMap:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        d = self.data
        self.class_count = int.from_bytes(d[0x20:0x24], 'little')
        self.entry_count = int.from_bytes(d[0x24:0x28], 'little')
        self.entry_base = 0x28
        self.class_off_base = self.entry_base + 16 * self.entry_count
        first = self.class_off_base + 4 * self.class_count
        self.dispatcher_class = cstr(d, first)
        self.string_base = d.index(0, first) + 1
    def entry(self, op):
        idx = opcode_to_index(op)
        if idx >= self.entry_count:
            return None
        off = self.entry_base + idx * 16
        raw = self.data[off:off+16]
        w0, name_rel, sig_rel, extra_rel = [int.from_bytes(raw[i:i+4], 'little') for i in range(0,16,4)]
        cls_idx = w0 >> 10
        cls_rel = int.from_bytes(self.data[self.class_off_base+4*cls_idx:self.class_off_base+4*cls_idx+4], 'little')
        return {
            'idx': idx, 'off': off, 'raw': raw.hex(), 'w0': w0,
            'flags': w0 & 0x1f, 'kind': (w0 >> 5) & 0x1f, 'class_idx': cls_idx,
            'cls': cstr(self.data, self.string_base + cls_rel),
            'name': cstr(self.data, self.string_base + name_rel),
            'sig': cstr(self.data, self.string_base + sig_rel),
            'extra': cstr(self.data, self.string_base + extra_rel),
        }

def type_desc(owner_no_l):
    if owner_no_l.startswith('L') and owner_no_l.endswith(';'):
        return owner_no_l
    if owner_no_l.startswith('['):
        return owner_no_l
    return 'L' + owner_no_l + ';'

def field_opcode(prefix, desc):
    if desc.startswith('L') or desc.startswith('['):
        return prefix + '-object'
    if desc in ('J','D'):
        return prefix + '-wide'
    if desc == 'Z':
        return prefix + '-boolean'
    if desc == 'B':
        return prefix + '-byte'
    if desc == 'C':
        return prefix + '-char'
    if desc == 'S':
        return prefix + '-short'
    return prefix

def move_opcode_for_desc(desc, dst, src, reg_count, param_words):
    # Use /from16 if either real register may be outside 4-bit move form.
    dst_hi = reg_abs_index(dst, reg_count, param_words) > 15
    src_hi = reg_abs_index(src, reg_count, param_words) > 15
    wide = desc in ('J', 'D')
    obj = desc.startswith('L') or desc.startswith('[')
    base = 'move-wide' if wide else ('move-object' if obj else 'move')
    if dst_hi or src_hi:
        return base + '/from16'
    return base

def move_object_to_low(dst_low, src, reg_count, param_words):
    # dst must be low; source may be p/high.
    if reg_abs_index(src, reg_count, param_words) > 15:
        return f'move-object/from16 {dst_low}, {src}'
    return f'move-object {dst_low}, {src}'

def parse_regs(regs_text):
    regs_text = regs_text.strip()
    if '..' in regs_text:
        a,b=[x.strip() for x in regs_text.split('..')]
        pref=a[0]
        ia=int(a[1:]); ib=int(b[1:])
        return [f'{pref}{i}' for i in range(ia, ib+1)], True
    return [x.strip() for x in regs_text.split(',') if x.strip()], False

def format_regs(regs, prefer_range=False):
    if not regs:
        return '{}'
    # Use /range if requested and registers are same prefix and contiguous.
    if prefer_range and len(regs) >= 2:
        pref = regs[0][0]
        nums = []
        ok = True
        for r in regs:
            if not r.startswith(pref): ok=False; break
            nums.append(int(r[1:]))
        if ok and nums == list(range(nums[0], nums[-1]+1)):
            return f'{{{regs[0]} .. {regs[-1]}}}'
    return '{' + ', '.join(regs) + '}'

def parse_const_val(s):
    return int(s, 0)

def desc_param_words(params):
    words = 0
    i = 0
    while i < len(params):
        c = params[i]
        while c == '[':
            i += 1
            if i >= len(params):
                return words + 1
            c = params[i]
        if c == 'L':
            j = params.find(';', i)
            i = len(params) if j < 0 else j + 1
            words += 1
        else:
            words += 2 if c in ('J','D') else 1
            i += 1
    return words

def reg_abs_index(reg, reg_count, param_words):
    if reg.startswith('v'):
        return int(reg[1:])
    if reg.startswith('p'):
        if reg_count is None or param_words is None:
            return 10**9
        return reg_count - param_words + int(reg[1:])
    return 10**9

def regs_fit_4bit(regs, reg_count, param_words):
    return all(reg_abs_index(r, reg_count, param_words) <= 15 for r in regs)

def next_nontrivia(lines, start):
    """Return index of next real instruction-ish line, skipping blank/comment/.line."""
    j = start
    while j < len(lines):
        t = lines[j].strip()
        if t == '' or t.startswith('#') or t.startswith('.line'):
            j += 1
            continue
        return j
    return None

def collect_interfaces(smali_root):
    interfaces=set(KNOWN_INTERFACES)
    for p in Path(smali_root).rglob('*.smali'):
        try:
            first = p.read_text(errors='replace').splitlines()[:8]
        except Exception:
            continue
        text='\n'.join(first)
        m=CLASS_RE.search(text)
        if m and INTERFACE_RE.search(text):
            interfaces.add(m.group(1))
    return interfaces

def method_invoke_kind(entry, owner_desc, interfaces):
    flags = entry['flags']
    name = entry['name']
    if flags == 0:
        return 'invoke-static'
    if flags == 1 or name == '<init>':
        return 'invoke-direct'
    if flags == 2:
        if owner_desc in interfaces or owner_desc.startswith('Lkotlin/jvm/functions/'):
            return 'invoke-interface'
        return 'invoke-virtual'
    # Fallback: most non-static callable entries with receiver are virtual.
    return 'invoke-virtual'

def patch_one(lines, dp, interfaces, file_rel, skip_methods=False, method_owner_prefixes=None):
    if method_owner_prefixes is None:
        method_owner_prefixes = []
    out=[]
    last_const={}
    stats=Counter()
    examples=[]
    i=0
    current_method_decl = None
    current_param_words = None
    current_registers = None
    while i < len(lines):
        line=lines[i]
        mm = METHOD_RE.match(line)
        if mm:
            current_method_decl = mm.group('decl')
            current_param_words = desc_param_words(mm.group('params')) + (0 if ' static ' in (' ' + current_method_decl + ' ') else 1)
            current_registers = None
            out.append(line); i += 1; continue
        rm = REGISTERS_RE.match(line)
        if rm and current_method_decl is not None:
            current_registers = int(rm.group('n'))
            out.append(line); i += 1; continue
        if line.strip() == '.end method':
            current_method_decl = None
            current_param_words = None
            current_registers = None
            out.append(line); i += 1; continue
        m_const = CONST_RE.match(line) or CONST_WIDE_RE.match(line)
        if m_const:
            try: last_const[m_const.group('reg')] = parse_const_val(m_const.group('val'))
            except Exception: pass
            out.append(line); i+=1; continue
        m_move = MOVE_INT_RE.match(line)
        if m_move:
            src = m_move.group('src'); dst = m_move.group('dst')
            if src in last_const:
                last_const[dst] = last_const[src]
            else:
                last_const.pop(dst, None)
            out.append(line); i+=1; continue

        m = INVOKE_RE.match(line)
        if not m:
            out.append(line); i+=1; continue

        stats['calls'] += 1
        indent=m.group('indent')
        regs, was_range = parse_regs(m.group('regs'))
        if not regs or regs[0] not in last_const:
            stats['unresolved_opcode'] += 1
            out.append(line); i+=1; continue
        op=last_const[regs[0]]
        ent=dp.entry(op)
        if not ent:
            stats['bad_entry'] += 1
            out.append(line); i+=1; continue

        owner = type_desc(ent['cls'])
        name = ent['name']
        sig = ent['sig']
        ret = m.group('ret')
        args = regs[1:]
        comment = f'    # dp: opcode={signed32(op)} idx=0x{ent["idx"]:x} kind={ent["kind"]} flags={ent["flags"]} {owner}->{name}{sig} extra={ent["extra"]}'
        patched = None
        consume_next = False

        # new-instance pseudo-entry returns object and is followed by move-result-object.
        if name == '<new-instance>':
            j = next_nontrivia(lines, i + 1)
            if j is not None:
                mr = MOVE_RESULT_RE.match(lines[j])
                if mr and mr.group('suffix') == '-object':
                    dst = mr.group('dst')
                    patched = [comment, f'{indent}new-instance {dst}, {sig if sig.startswith("L") else owner}']
                    consume_next = j
                    stats['new_instance'] += 1
        # Field ops: field signature has no method params.
        elif not sig.startswith('('):
            field_ref = f'{owner}->{name}:{sig}'
            if ret == 'V':
                if ent['flags'] in (4,):   # instance put
                    if len(args) >= 2 and regs_fit_4bit([args[0], args[1]], current_registers, current_param_words):
                        opx = field_opcode('iput', sig)
                        patched = [comment, f'{indent}{opx} {args[1]}, {args[0]}, {field_ref}']
                        stats['iput'] += 1
                elif ent['flags'] in (6,): # static put
                    if len(args) >= 1:
                        opx = field_opcode('sput', sig)
                        patched = [comment, f'{indent}{opx} {args[0]}, {field_ref}']
                        stats['sput'] += 1
            else:
                j = next_nontrivia(lines, i + 1)
                if j is not None:
                    mr = MOVE_RESULT_RE.match(lines[j])
                    if mr:
                        dst = mr.group('dst')
                        if ent['flags'] in (3,):
                            if len(args) >= 1 and regs_fit_4bit([dst, args[0]], current_registers, current_param_words):
                                opx = field_opcode('iget', sig)
                                patched = [comment, f'{indent}{opx} {dst}, {args[0]}, {field_ref}']
                                consume_next = j
                                stats['iget'] += 1
                            elif len(args) >= 1:
                                # 22c iget needs 4-bit registers. If p/high regs are involved,
                                # reuse the opcode register as a low temp; the opcode const is dead after patching.
                                temp = regs[0]
                                temp_abs = reg_abs_index(temp, current_registers, current_param_words)
                                if temp_abs <= (14 if sig in ('J','D') else 15):
                                    opx = field_opcode('iget', sig)
                                    obj = args[0]
                                    seq = [comment]
                                    obj_for = obj
                                    if reg_abs_index(obj, current_registers, current_param_words) > 15:
                                        seq.append(f'{indent}{move_object_to_low(temp, obj, current_registers, current_param_words)}')
                                        obj_for = temp
                                    seq.append(f'{indent}{opx} {temp}, {obj_for}, {field_ref}')
                                    if dst != temp:
                                        mop = move_opcode_for_desc(sig, dst, temp, current_registers, current_param_words)
                                        seq.append(f'{indent}{mop} {dst}, {temp}')
                                    patched = seq
                                    consume_next = j
                                    stats['iget_temp'] += 1
                        elif ent['flags'] in (5,):
                            opx = field_opcode('sget', sig)
                            patched = [comment, f'{indent}{opx} {dst}, {field_ref}']
                            consume_next = j
                            stats['sget'] += 1
        # Method ops.
        elif sig.startswith('('):
            if skip_methods or (method_owner_prefixes and not any(ent['cls'].startswith(pref) for pref in method_owner_prefixes)):
                stats['method_skipped'] += 1
                patched = None
            else:
                invoke = method_invoke_kind(ent, owner, interfaces)
                regs_text = format_regs(args, prefer_range=bool(m.group('range')))
                suffix = '/range' if (m.group('range') and '..' in regs_text) else ''
                if suffix and not invoke.endswith('/range'):
                    invoke += suffix
                patched = [comment, f'{indent}{invoke} {regs_text}, {owner}->{name}{sig}']
                stats[invoke.replace('/range','')] += 1

        if patched:
            out.extend(patched)
            if consume_next is not False:
                i = consume_next + 1
            else:
                i += 1
        else:
            stats['unsupported'] += 1
            if len(examples) < 20:
                examples.append((file_rel, i+1, op, ent, line.strip()))
            out.append(line)
            i += 1
    return out, stats, examples

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', default='build/classes0_smali')
    ap.add_argument('--out', dest='out', default='build/classes0_smali_patched')
    ap.add_argument('--dp', default='dumps/ic_dat_dumps/dp_mp3_decompressed.bin')
    ap.add_argument('--skip-methods', action='store_true', help='Do not replace method invoke dispatcher entries; keeps method_id count low')
    ap.add_argument('--method-owner-prefix', action='append', default=[], help='Only patch method entries whose owner starts with this slash name prefix; can repeat')
    ap.add_argument('--no-clean', action='store_true')
    args=ap.parse_args()

    inp=Path(args.inp); out=Path(args.out)
    if not args.no_clean and out.exists(): shutil.rmtree(out)
    if not out.exists(): shutil.copytree(inp, out)

    dp=DpMap(args.dp)
    interfaces=collect_interfaces(inp)
    total=Counter(); unsupported=[]; files_changed=0
    for p in sorted(out.rglob('*.smali')):
        rel=p.relative_to(out)
        lines=p.read_text(errors='replace').splitlines()
        patched, st, ex = patch_one(lines, dp, interfaces, str(rel), skip_methods=args.skip_methods, method_owner_prefixes=args.method_owner_prefix)
        if patched != lines:
            p.write_text('\n'.join(patched) + '\n')
            files_changed += 1
        total.update(st)
        unsupported.extend(ex)

    print(f'input={inp}')
    print(f'output={out}')
    print(f'dp={args.dp} dispatcher_class={dp.dispatcher_class} entries=0x{dp.entry_count:x}')
    print(f'files_changed={files_changed}')
    for k,v in total.most_common():
        print(f'{k}={v}')
    if unsupported:
        print('\nunsupported examples:')
        for rel,ln,op,e,line in unsupported[:20]:
            print(f'{rel}:{ln}: op={signed32(op)} idx=0x{e["idx"]:x} kind={e["kind"]} flags={e["flags"]} {e["cls"]}->{e["name"]}{e["sig"]} ret/line={line}')

if __name__ == '__main__':
    main()
