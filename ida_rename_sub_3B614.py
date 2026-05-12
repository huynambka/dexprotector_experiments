import ida_name

# Rename manual symbol resolver in unpacked DexProtector image.
ea = 0x3B614
new_name = "manual_dlsym_from_r_debug"
ida_name.set_name(ea, new_name, ida_name.SN_CHECK | ida_name.SN_FORCE)
print(f"renamed 0x{ea:x} -> {new_name}")
