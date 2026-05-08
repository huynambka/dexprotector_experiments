# Run in IDA: File -> Script file... -> ida_rename_plt_again.py
# Creates missing 16-byte PLT stub functions and renames all PLT entries for unpacked libdp image.
import ida_funcs
import ida_name
import idc

PLT = [
    (0x7c910, 'plt_malloc'),
    (0x7c920, 'plt_calloc'),
    (0x7c930, 'plt_free'),
    (0x7c940, 'plt_realloc'),
    (0x7c950, 'plt_getauxval'),
    (0x7c960, 'plt_gmtime_r'),
    (0x7c970, 'plt_time'),
    (0x7c980, 'plt___android_log_print'),
    (0x7c990, 'plt_AAssetManager_fromJava'),
    (0x7c9a0, 'plt___android_log_write'),
    (0x7c9b0, 'plt_AAssetManager_openDir'),
    (0x7c9c0, 'plt_AAssetDir_getNextFileName'),
    (0x7c9d0, 'plt_AAsset_close'),
    (0x7c9e0, 'plt_AAssetManager_open'),
    (0x7c9f0, 'plt_AAsset_getBuffer'),
    (0x7ca00, 'plt_AAsset_getLength'),
    (0x7ca10, 'plt_AAssetDir_close'),
    (0x7ca20, 'plt_funopen'),
    (0x7ca30, 'plt_setvbuf'),
    (0x7ca40, 'plt_pthread_create'),
    (0x7ca50, 'plt_pthread_detach'),
    (0x7ca60, 'plt_arc4random_buf'),
    (0x7ca70, 'plt_pthread_atfork'),
    (0x7ca80, 'plt_sigaction'),
    (0x7ca90, 'plt___system_property_get'),
]

# PLT0 resolver trampoline (not a normal imported function)
idc.set_cmt(0x7c8f0, 'PLT0/lazy resolver trampoline: stp x16,x30; load resolver from GOT; br x17. Hex-Rays JUMPOUT is normal.', 0)

for ea, name in PLT:
    # each AArch64 PLT entry here is 0x10 bytes: adrp; ldr; add; br
    if ida_funcs.get_func(ea) is None:
        ida_funcs.add_func(ea, ea + 0x10)
    ok = ida_name.set_name(ea, name, ida_name.SN_FORCE | ida_name.SN_NOWARN)
    print('%s 0x%x -> %s' % ('OK' if ok else 'FAIL', ea, name))

print('done')
