# IDAPython: normalize relocated internal pointers in the current raw unpacked image DB.
# Run in IDA: File -> Script file... -> select this file.
# It subtracts LOAD_BIAS from any qword in [LOAD_BIAS, LOAD_BIAS + IMAGE_SIZE).

import ida_bytes
import ida_auto
import ida_funcs

LOAD_BIAS = 0x73e4e3c000
IMAGE_START = 0x0
IMAGE_SIZE = 0x90000
IMAGE_END = IMAGE_START + IMAGE_SIZE

patched = []
for ea in range(IMAGE_START, IMAGE_END - 7, 8):
    v = ida_bytes.get_qword(ea)
    if LOAD_BIAS <= v < LOAD_BIAS + IMAGE_SIZE:
        nv = v - LOAD_BIAS
        ida_bytes.patch_qword(ea, nv)
        patched.append((ea, v, nv))

print('[normalize_internal_ptrs] load_bias=%#x image=[%#x,%#x)' % (LOAD_BIAS, IMAGE_START, IMAGE_END))
print('[normalize_internal_ptrs] patched %d qwords' % len(patched))
for ea, v, nv in patched[:100]:
    print('  %#x: %#x -> %#x' % (ea, v, nv))
if len(patched) > 100:
    print('  ... %d more' % (len(patched) - 100))

# Re-analyze main area and mark relevant function dirty for Hex-Rays.
try:
    ida_auto.plan_and_wait(IMAGE_START, IMAGE_END)
except Exception as e:
    print('[normalize_internal_ptrs] reanalysis failed:', e)

try:
    import ida_hexrays
    for fva in [0x3CE5C, 0x4E354, 0x7C380, 0x7C850]:
        try:
            ida_hexrays.mark_cfunc_dirty(fva)
        except Exception:
            pass
except Exception:
    pass

print('[normalize_internal_ptrs] done. Press F5 again on sub_3CE5C.')
