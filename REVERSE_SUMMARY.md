# DexProtector envchecks reversing notes

Workspace: `/home/namnh/research/dexprotector`  
Target package: `com.dexprotector.detector.envchecks`  
Main native libs: `arm64-v8a/libdexprotector.so`, `arm64-v8a/libalice.so`

---

## 1. Big picture

The app loads a small visible native loader, `libdexprotector.so`.
That loader contains an encrypted/packed payload inside its 4th `PT_LOAD`.
At runtime it:

1. disables dump/debug behavior with syscalls,
2. finds `auxv`,
3. finds linker `r_debug`,
4. derives an unpack key,
5. decrypts/decompresses the hidden payload into anonymous memory,
6. acts like a custom linker: resolves imports and applies relocations,
7. runs the hidden payload's init-array constructors,
8. returns a hidden JNI entry function pointer,
9. exported `JNI_OnLoad()` calls that hidden entry.

The dumped unpacked payload is not a normal `.so` ELF file. It is a raw in-memory image containing ARM64 code, data, dynamic table, relocation tables, init/fini arrays, etc.

---

## 2. Important local files

### Original artifacts

```text
base.apk
split_config.arm64_v8a.apk
arm64-v8a/libdexprotector.so
arm64-v8a/libalice.so
```

### Frida scripts created/used

```text
trace_native_load_order_frida17.js
hook_linker_constructors_frida17.js
hook_dexprotector_key_frida17.js
hook_dexprotector_key_frida17.js.bak
hook_dexprotector_spoof_sub918_frida17.js
spoof_key.js
hook_sub_DAC.js
hook_sub_DAC_mmap.js
hook_dump_unpacked_chunks.js
hook_dump_after_reloc_frida17.js
hook_dump_unpacked_and_reloc_frida17.js
hook_dump_unpacked_and_reloc_leaveonly_frida17.js
hook_init_decoders_frida17.js
hook_sub_3CE5C_frida17.js
hook_sub_367A8_jni_calls_frida17.js
hook_sub_374A0_jni_refs_frida17.js
hook_sub_3C3FC_fileio_frida17.js
hook_sub_3C3FC_fileio_safe_frida17.js
hook_sub_363F0_decode_v0_v1_frida17.js
hook_unpacked_fn_args_ret_frida17.js
bypass_dex_frida17.js
ida_rename_plt_again.py
ida_normalize_internal_ptrs.py
ida_rename_sub_3B614.py
ida_decode_sub_401B0.py
ida_comment_decode_calls.py
merge_relocated_with_metadata.py
normalize_internal_reloc_ptrs.py
```

### Dumped unpacked chunks

```text
dumps/chunk_00.bin              size 0x7caa0
dumps/chunk_01.bin              size 0x4208
dumps/chunk_02.bin              size 0x1a5c
dumps/unpacked_image_0x90000.bin
dumps/chunk_00_embedded.dex
```

---

## 3. `libalice.so` summary

`libalice.so` is a larger environment/device/security collection library.

Important points:

- `JNI_OnLoad` at RVA `0x2a22c`.
- Registers native methods on:

```text
com/dexprotector/detector/envchecks/ProtectedApplication$MainActivity$$ExternalSyntheticLambda1
```

- Has custom string decryptor around `0x46358`.
- Contains endpoints/strings:

```text
https://aws-gate.licelus.com:9443/api/send
https://amdb.alice.licelus.com/v4/am_idx.dat
ict.dat
DEXP-HMAC-SHA256
Authorization
```

- Collects environment/build/camera/sensor/key-attestation style data.

Native table found:

```text
E0  a (Ljava/lang/String;)V                                      0x24994
E1  a (Landroid/content/Context;)V                               0x29c18
E2  a ([BJ)Ljava/net/HttpURLConnection;                          0x293fc
E3  b (Ljava/lang/String;)Ljava/net/HttpURLConnection;            0x29a60
E4  a ()Z                                                        0x29f1c
E5  b ()Ljava/lang/String;                                       0x29f60
E6  a (Ljava/lang/String;Ljava/lang/String;IZLjava/util/List;ILjava/lang/String;I)V 0x28574
E7  a (Ljava/lang/String;Ljava/lang/String;IZLjava/util/List;Ljava/util/List;ILjava/lang/String;I)V 0x282e0
E8  a (Ljava/lang/Throwable;)Ljava/lang/String;                  0x27d20
E9  c (Ljava/lang/String;)V                                      0x28a40
E10 a (ILjava/lang/String;)Ljava/lang/String;                    0x29194
E11 a (ILjava/lang/String;Z)Ljava/lang/String;                   0x27298
E12 b (Landroid/content/Context;)V                               0x2a150
```

---

## 4. `libdexprotector.so` outer loader

`libdexprotector.so` is:

```text
ELF 64-bit ARM64 shared object, static-pie linked, stripped
```

Important exported/loader functions:

```text
.init_array[0] = base + 0x378
JNI_OnLoad     = 0x440
```

### Constructor `sub_378`

`sub_378()` runs from `.init_array` before exported `JNI_OnLoad()`.

It:

1. calls `prctl(PR_SET_DUMPABLE, 0)` using syscall `0xa7`,
2. parses own ELF program headers,
3. finds the 4th `PT_LOAD`,
4. calls:

```c
sub_2434(base + 0xf630, 0x588d9)
```

5. stores return function pointer in global `off_B230`,
6. stores error/status in `dword_B228`.

If no 4th PT_LOAD:

```text
dword_B228 = 404
JNI_OnLoad returns -404
```

If unpack/link fails:

```text
dword_B228 = 500
JNI_OnLoad returns -500
```

### Exported `JNI_OnLoad`

```c
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    if (dword_B228)
        return -dword_B228;

    ret = off_B230(vm, 0);
    off_B230 = NULL;

    if (ret)
        return -ret;

    return JNI_VERSION_1_4; // 0x10004
}
```

So exported `JNI_OnLoad` is only a trampoline into the hidden unpacked entry.

---

## 5. Small string decryptor `sub_25B8`

Offset/RVA:

```text
sub_25B8 = 0x25B8
```

It is a stream-XOR decryptor, not simple encoding.

Prototype-like:

```c
char *sub_25B8(uint8_t *blob, char *out, size_t len);
```

Blob layout:

```text
blob[0:8] = seed
blob[8:]  = ciphertext
```

Static table/key at `base + 0x2d7`:

```text
c7 31 4a 34 10 96 26 2f ce 56 de 59 a6 67 07 08
84 21 ce 1c cf 62 23 fa a5 8c 1f be 5a 29 99 6f
```

U32 LE:

```text
0x344a31c7
0x2f269610
0x59de56ce
0x080767a6
0x1cce2184
0xfa2362cf
0xbe1f8ca5
0x6f99295a
```

Example decoded string:

```text
/proc/self/stat\0
```

---

## 6. `sub_2220`: find auxv from `/proc/self/stat`

`sub_2220()` does:

1. decrypts `/proc/self/stat`,
2. syscall `openat(AT_FDCWD, "/proc/self/stat", O_RDONLY)`, syscall number `56`,
3. syscall `read(fd, buf, 0xfff)`, syscall number `63`,
4. syscall `close(fd)`, syscall number `57`,
5. finds last `')'` using `sub_748`,
6. parses field 28 from `/proc/self/stat`.

Field 28 is:

```text
startstack
```

Then it walks the process initial stack:

```c
sp = startstack;
argc = sp[0];
sp = sp + argc + 2;     // skip argc, argv..., argv NULL
while (*sp) sp++;       // skip envp
while (*sp == 0) sp++;  // skip NULL padding
return sp;              // auxv pointer
```

So `sub_2220()` returns auxiliary vector address.

---

## 7. `sub_2358`: find `r_debug`

`sub_2358(auxv)` returns `struct r_debug *`.

It reads auxv tags:

```text
AT_PHNUM = 5
AT_PHDR  = 3
```

Then it scans the main executable program headers for:

```text
PT_PHDR    = 6
PT_DYNAMIC = 2
```

Computes main executable load base:

```c
base = runtime_PT_PHDR_addr - PT_PHDR.p_vaddr;
dynamic = base + PT_DYNAMIC.p_vaddr;
```

Then scans dynamic entries for:

```text
DT_DEBUG = 0x15
```

`DT_DEBUG` points to `r_debug`.

Important field:

```text
r_debug + 0x10 = r_brk
```

On Android, `r_brk` usually points to linker debugger callback, often `rtld_db_dlactivity()`.

---

## 8. `sub_918`: derive unpack key

`sub_918()` derives the 32-byte key used by the packed payload decryptor.

It:

1. runs an obfuscated constants VM,
2. gets a fixed raw key,
3. XORs four bytes of the key with first instruction bytes from `r_debug->r_brk`.

Raw VM key:

```text
9b85ecd2ebec18cf24758bdd14df3e03b430508aa690a5006ef23f3c8b7d8ca2
```

If `r_brk` starts with BTI instruction `0xd503245f`, it skips 4 bytes.

Then it does:

```c
key[0]  ^= p[0];
key[4]  ^= p[1];
key[8]  ^= p[2];
key[12] ^= p[3];
```

Observed real Pixel `r_brk` first bytes:

```text
e4 4c 05 14
```

Real final key observed:

```text
7f85ecd2a7ec18cf21758bdd00df3e03b430508aa690a5006ef23f3c8b7d8ca2
```

If spoofing `ret` bytes `c0 03 5f d6`, expected final key would be:

```text
5b85ecd2e8ec18cf7b758bddc2df3e03b430508aa690a5006ef23f3c8b7d8ca2
```

Spoof attempt did not fully succeed because the loader uses real callback bytes and/or timing/state is sensitive.

---

## 9. Cipher functions

Renames used in IDA:

```text
sub_D4C  -> dp_cipher_ctx_zero
sub_D60  -> dp_cipher_set_key
sub_DAC  -> dp_stream_xor_crypt
sub_1290 -> dp_unpack_payload
sub_918  -> dp_derive_unpack_key
sub_1C5C -> lz4_decompress_block
sub_63C  -> memset_local
```

### `sub_D4C(ctx)`

Zeroes 0x38-byte cipher context.

### `sub_D60(ctx, key)`

Copies 32-byte key to context.

### `sub_DAC(ctx, len, in, out)`

Stream-XOR encrypt/decrypt.

Context layout:

```text
ctx+0x00  position
ctx+0x08  counter/seed
ctx+0x10  current 8-byte keystream block
ctx+0x18  key[8] / 32-byte key
```

---

## 10. `sub_1290` / `dp_unpack_payload`

This function decrypts and decompresses the hidden payload.

Arguments:

```c
dp_unpack_payload(packed_blob, packed_size, r_debug, unpack_state)
```

Main stages:

1. derive unpack key with `sub_918`,
2. initialize stream cipher,
3. decrypt 36-byte packed header,
4. mmap anonymous memory,
5. compute aligned base and `load_bias`,
6. loop chunk descriptors,
7. decrypt each compressed chunk,
8. LZ4-decompress each chunk into mmap image,
9. checksum each output chunk,
10. save mprotect/protection info in `unpack_state`.

### Decrypted 36-byte header

Hex:

```text
000009000000000040000000080000006049080000000800008000000040000003000000
```

LE fields:

```text
hdr[0] = 0x00090000  mmap/map size base
hdr[1] = 0x00000000  bias_sub
hdr[2] = 0x00000040  unknown
hdr[3] = 0x00000008  unknown
hdr[4] = 0x00084960  dynamic table pointer offset
hdr[5] = 0x00080000  extra region offset
extra_region_size = 0x8000
alignment         = 0x4000
chunk_count       = 3
```

Runtime calculations:

```c
mmap_size = hdr[0] + alignment;       // 0x94000
aligned_base = align_up(mmap_base, alignment);
load_bias = aligned_base - bias_sub;  // bias_sub is 0 here
state[2] = load_bias;
state[3] = load_bias + hdr[4];        // dynamic table
```

### `bias_sub`

`bias_sub` is like ELF loader bias correction.

Custom linker wants to use virtual addresses from the unpacked image. Runtime address is:

```c
runtime = load_bias + virtual_offset;
```

If the payload expected a nonzero minimum virtual address, `bias_sub` would compensate. In this sample it is zero.

---

## 11. Chunk layout and dumped files

The packed payload has three chunks.

Runtime offsets:

```text
chunk_00 -> 0x00000
chunk_01 -> 0x80aa0
chunk_02 -> 0x88cb0
```

Sizes dumped after LZ4 decompression:

```text
chunk_00.bin  0x7caa0
chunk_01.bin  0x4208
chunk_02.bin  0x1a5c
```

Do not concatenate directly. Need preserve gaps.

Combined image command:

```bash
python3 - <<'PY'
from pathlib import Path

out = bytearray(b'\x00' * 0x90000)

chunks = [
    ("dumps/chunk_00.bin", 0x00000),
    ("dumps/chunk_01.bin", 0x80aa0),
    ("dumps/chunk_02.bin", 0x88cb0),
]

for path, off in chunks:
    data = Path(path).read_bytes()
    out[off:off+len(data)] = data
    print(path, hex(off), hex(off+len(data)), len(data))

Path("dumps/unpacked_image_0x90000.bin").write_bytes(out)
print("wrote dumps/unpacked_image_0x90000.bin", len(out))
PY
```

Result:

```text
dumps/unpacked_image_0x90000.bin size 0x90000
```

---

## 12. `sub_1C5C`: decompressor

`sub_1C5C(src, dst, compressed_size, expected_output_size)` is a custom/inlined LZ4 block decompressor.

Pattern:

```text
token high nibble -> literal length
token low nibble  -> match length
extra length bytes
2-byte match offset
match length + 4
```

`dp_unpack_payload` checks:

```c
sub_1C5C(...) == expected_output_size
```

---

## 13. `sub_167C`: custom linker / relocation fixer

Called by `sub_2434()` after chunks are unpacked:

```c
sub_167C(dynamic_ptr, load_bias, auxv, r_debug)
```

Meaning:

```text
a1 = dynamic section of unpacked payload
a2 = load_bias
a3 = auxv
a4 = r_debug
```

It is not decrypt/decompress. It makes unpacked memory runnable.

### It scans dynamic table for:

```text
DT_PLTRELSZ     = 2
DT_STRTAB       = 5
DT_SYMTAB       = 6
DT_RELA         = 7
DT_RELASZ       = 8
DT_STRSZ        = 10
DT_JMPREL       = 23
DT_RELRSZ       = 35
DT_RELR         = 36
DT_RELRENT      = 37
```

### It resolves imports

Calls:

```c
sub_E8C(resolver_ctx, dynamic, strtab, auxv, r_debug)
```

`sub_E8C` handles `DT_NEEDED`:

1. read needed library names from string table,
2. walk `r_debug->r_map`,
3. compare loaded library basenames,
4. parse each dependency dynamic section with `sub_10A8`,
5. build resolver slots for up to 8 libraries.

Needed libs found:

```text
libc.so
liblog.so
libandroid.so
```

SONAME:

```text
libdp.so
```

### It applies relocations

Calls roughly:

```c
sub_1820(load_bias, rela_table, rela_size, resolver_ctx, symtab_strtab);
sub_1820(load_bias, jmprel_table, pltrelsz, resolver_ctx, symtab_strtab);
```

Then:

```c
sub_19EC(load_bias, relr_table, relr_size);
```

So it fixes:

```text
.rela.dyn
.rela.plt / JMPREL
DT_RELR compact relative relocations
```

### It hides metadata

After resolving imports:

```c
memset(symtab, 0, strtab + strsz - symtab);
```

This wipes symbol/string table data to make later analysis harder.

---

## 14. `sub_2434`: high-level flow and return value

`sub_2434()` flow:

```text
sub_2220()       -> find auxv
sub_2358(auxv)  -> find r_debug
sub_1290(...)   -> decrypt + decompress payload into mmap memory
sub_167C(...)   -> custom linker work: imports + relocations
parse dynamic    -> find init_array/fini_array
sub_15E0(state) -> restore final mprotect permissions
call init_array functions
sub_1658(state) -> final protect/seal
return last fini_array entry
```

### When is linker work done?

Core relocation/import linking is done when:

```c
sub_167C(...) returns 1
```

Fully loaded/runnable is after:

```c
sub_15E0(...)
init_array calls
sub_1658(...)
return
```

### Init array really runs

`sub_2434()` does not only parse init array. It calls every init function:

```c
for (; init_count; ++init_array) {
    fn = *init_array;
    *init_array = 0;
    if ((uint64_t)fn + 1 >= 2)
        state = fn(state);
}
```

### Return value

`sub_2434()` returns the last `DT_FINI_ARRAY` entry.

In this dump:

```text
DT_FINI_ARRAY   = 0x84958
DT_FINI_ARRAYSZ = 0x8
[0x84958]       = 0x4e354
```

Therefore:

```text
sub_2434 returns load_bias + 0x4e354
```

In raw IDA image base 0:

```text
0x4e354 = sub_4E354
```

This is the hidden JNI entry called by exported `JNI_OnLoad()`.

---

## 15. Dynamic table in dumped image

Combined raw image:

```text
dumps/unpacked_image_0x90000.bin
```

Dynamic table offset:

```text
0x84960
```

Useful entries:

```text
0x84960  DT_NEEDED       0x17e      -> liblog.so
0x84970  DT_NEEDED       0x188      -> libandroid.so
0x84980  DT_NEEDED       0x171      -> libc.so
0x84990  DT_SONAME       0x161      -> libdp.so
0x849c0  DT_RELR         0x6b8
0x849d0  DT_RELRSZ       0x148
0x849e0  DT_RELRENT      0x8
0x849f0  DT_JMPREL       0x800
0x84a00  DT_PLTRELSZ     0x258
0x84a10  DT_PLTGOT       0x84bc8
0x84a30  DT_SYMTAB       0x200
0x84a50  DT_STRTAB       0x51c
0x84a60  DT_STRSZ        0x196
0x84a80  DT_INIT_ARRAY   0x84920
0x84a90  DT_INIT_ARRAYSZ 0x38
0x84aa0  DT_FINI_ARRAY   0x84958
0x84ab0  DT_FINI_ARRAYSZ 0x8
```

### Init array functions

```text
0x84920: 0x7c380
0x84928: 0x7c850
0x84930: 0x3ce5c
0x84938: 0x37ff8
0x84940: 0x40194
0x84948: 0x552f8
0x84950: 0x4eb60
```

Current meaning of each init-array entry:

```text
0x7c380  init_lse_atomics_flag_blacklist_exynos9810
         Reads getauxval(AT_HWCAP), checks LSE atomics support, then reads ro.arch.
         If ro.arch == "exynos9810", disables LSE atomics workaround flag.

0x7c850  small runtime/compiler constructor stub. Not reversed deeply yet.

0x3ce5c  init_decode_global_108byte_blob
         malloc(0x6c), writes first decoded 108-byte blob, stores heap ptr in qword_891B0.
         This first content is temporary; next init overwrites same heap buffer.

0x37ff8  init_generate_global_108byte_table
         Uses encoded seed at 0x89160. First XOR-decodes 0x40 bytes with 0x5a,
         expands/generates final 108-byte table into the heap buffer pointed by qword_891B0,
         then wipes seed 0x89160..0x8919f to zero.
         Final qword_891B0 / qword_8CB40 table verified by static emulation of sub_37FF8:
         61d5ccc1cc0659b29b30e842f6fab3bd15edef6db465bf039775912d6e499aa20942d5d627bcafb8382f0055894fc3797529cb2ce6ec025423c8c33f6fd8b88065f72dca2a77a28a86a432549aab97cfa325cea8c96bbe3c0430df004b234a70dde895c6bd53d420909ae98a
         Verification strings decoded with sub_401B0:
           0x4143 len 15 -> /proc/self/exe
           0x3991 len 8  -> libc.so
           0x3406 len 22 -> __system_property_get
           0x2DCF len 21 -> ro.build.version.sdk
         Note: older note/table beginning `61d5ccc16f7e...` was wrong.

0x40194  init_copy_decoded_blob_ptr_to_8CB40
         Runtime: qword_8CB40 = qword_891B0.
         IDA may show qword_8CB40 = 0 because static qword_891B0 is zero;
         at runtime sub_3CE5C has already written malloc ptr to qword_891B0.

0x552f8  init_decode_stream_cipher_table_8D0B0
         Pairwise XOR-decodes 64-byte source byte_89CD8 into 32-byte byte_8D0B0,
         then wipes byte_89CD8..byte_89D17 to 0xff.
         Runtime byte_8D0B0 observed:
         409caaa073ababf511b77716d26f423eac819d50a5e838290eacf5ee1f904a13
         This is used by sub_55610 as 8 little-endian u32 key/table words:
         {0xa0aa9c40, 0xf5abab73, 0x1677b711, 0x3e426fd2,
          0x509d81ac, 0x2938e8a5, 0xeef5ac0e, 0x134a901f}
         sub_55610 is a stream decoder: blob[0:8] seed/state, blob[8:] ciphertext, out=keystream^ciphertext.
         byte_8D0B0 is NOT used by sub_4EB60.

0x4eb60  init_compute_code_siphash_baseline
         Computes qword_8CEF8 = SipHash-2-4(image+0x10e00, 0x663e8, zero_key).
         Range is 0x10e00..0x771e8. Expected hash from dump: 0xf87bb65e6fb11a5f.
         This init only computes/stores baseline; it does not check it.
         Later hidden JNI entry 0x4e354 recomputes and compares against qword_8CEF8.
```

### Fini array / hidden entry

```text
0x84958: 0x4e354
```

---

## 16. IDA loading notes for unpacked image

Open:

```text
dumps/unpacked_image_0x90000.bin
```

Use:

```text
File type: Binary file
Processor: ARM Little-endian / AArch64
Base/loading address: 0x0
ROM start: 0x0
ROM size: 0x90000
Loading size: 0x90000
```

Do not create RAM section unless needed.

After load, go to important addresses and make code/function:

```text
C -> make code
P -> make function
F5 -> decompile
```

Important addresses:

```text
0x4e354   hidden JNI entry / returned by sub_2434
0x4e7d8   likely error/exception throw path
0x7c380   init_array[0]
0x7c850   init_array[1]
0x3ce5c   init_array[2]
0x37ff8   init_array[3]
0x40194   init_array[4]
0x552f8   init_array[5]
0x4eb60   init_array[6]
```

Test for correct ARM64 mode at `0x7c380`:

```asm
PACIASP
SUB SP, SP, #0x70
STP X30, X19, [SP,#0x60]
```

---

## 17. `sub_4E354`: hidden JNI entry

IDA decompiled `sub_4E354` from the unpacked image.

It starts like a real JNI init:

```c
vm->GetEnv(&env, JNI_VERSION_1_4);
```

IDA line:

```c
if (vm->functions->GetEnv(vm, &env, 65540))
    return 1201;
```

`65540 = 0x10004 = JNI_VERSION_1_4`.

So `sub_4E354(JavaVM *vm)` is the hidden payload's JNI entry.

High-level behavior:

1. get `JNIEnv`,
2. run many anti-debug/environment/integrity checks,
3. if any fail, call `sub_4E7D8(env, error_code)`,
4. likely throws `MessageGuardException`,
5. if checks pass, uses JNI class/method operations and continues native init.

### Syscalls seen inside `sub_4E354`

```text
syscall 164 = setrlimit
syscall 172 = getpid
syscall 167 = prctl
```

It appears to disable core dumps and manipulate ptrace/debug behavior.

`prctl` value:

```text
0x59616D61 = PR_SET_PTRACER
```

### Failure style

Many checks have this shape:

```c
v7 = sub_374A0(env);
if (v7) fail;

v7 = sub_367A8(env);
if (v7) fail;

...

fail:
return sub_4E7D8(env, v7);
```

This matches observed crash with huge `MessageGuardException_...` string.

---

## 18. Java/JADX findings

Important classes:

```text
ProtectedApplication
MessageGuardException
ProtectedApplication$ProtectedApplication$KeystoreUtils
```

`ProtectedApplication.attachBaseContext()`:

```java
KeystoreUtils.m1195a(this);
if (!Aud) {
    ejIoucng();              // cert SHA-256 check
    System.loadLibrary("dexprotector");
}
```

`ProtectedApplication.onCreate()`:

```java
KeystoreUtils.m1198c(this);
if (!Aud) {
    ye();                    // native protected check/init
}
```

`MessageGuardException`:

```java
class MessageGuardException extends RuntimeException {
    String msg;
    public String toString() {
        return getClass().getName() + "_" + msg;
    }
}
```

Crash after successful unpack is intentional native guard failure, not necessarily unpack failure.

---

## 19. Frida runtime dumping

`hook_dump_unpacked_chunks.js` hooks `sub_1C5C` after decompression and dumps destination buffers.

Observed dump log shape:

```text
[lz4 dump] idx=0 dst=... comp=0x55932 out=0x7caa0 ret=0x7caa0
[lz4 dump] idx=1 dst=... comp=0x157e  out=0x4208  ret=0x4208
[lz4 dump] idx=2 dst=... comp=0x19b9  out=0x1a5c  ret=0x1a5c
```

Dump path on device:

```text
/data/data/com.dexprotector.detector.envchecks/files/dp_unpack_dumps
```

Pull examples:

```bash
adb shell 'su -c "ls -l /data/data/com.dexprotector.detector.envchecks/files/dp_unpack_dumps"'
adb shell 'su -c "cat /data/data/com.dexprotector.detector.envchecks/files/dp_unpack_dumps/chunk_00.bin"' > dumps/chunk_00.bin
```

`run-as` failed because package is not debuggable, so `su` was used.

---

## 20. Important mistake avoided

Hooking at the wrong instruction between compare and branch can crash.

Example in `hook_sub_DAC_mmap.js`:

- hooking right after syscall but before condition branch may clobber NZCV flags,
- safer hook point was after branch decision, around `base + 0x1354`.

General rule:

```text
Do not place Frida Interceptor exactly between CMP/CMN and conditional branch.
```

---

## 21. Current understanding of crash

Observed crash:

```text
com.dexprotector.detector.envchecks.MessageGuardException_...
```

Interpretation:

- unpacking succeeded,
- hidden payload executed,
- hidden native guard detected something,
- guard threw `MessageGuardException` with encoded/huge message.

Likely failure path:

```text
sub_4E354 -> check returns error code -> sub_4E7D8(env, code) -> Java exception
```

So next target is not unpack anymore. Next target is hidden guard bypass / exact failing check identification.

---

## 22. Good next reversing ideas

### A. Analyze `sub_4E7D8`

Goal: confirm exception construction and log error code.

Ideas:

- decompile `0x4e7d8`,
- rename it `throw_message_guard_exception`,
- hook it with Frida:

```js
Interceptor.attach(base.add(0x4e7d8), {
  onEnter(args) {
    console.log('[sub_4E7D8] env=' + args[0] + ' code=' + args[1]);
  }
});
```

Because unpacked image is anonymous memory, need compute runtime base/load_bias first.
Can get it from existing unpack hooks: `state[2] = load_bias`.

### B. Hook each check in `sub_4E354`

Functions called from `sub_4E354` that return error code:

```text
0x374A0
0x367A8
0x3B6D8
0x363F0
0x5E38C
0x63EA8
0x5C4A4
0x5CB1C
0x5D6F0
0x3601C
0x3662C
0x59F40
0x36764
0x5E684
0x4EB9C
```

Hook onLeave for each and print nonzero return value.

### C. Patch failed checks to return 0

Once failing function is known, patch/hook:

```js
Interceptor.replace(load_bias.add(offset), new NativeCallback(function () {
  console.log('bypass check offset');
  return 0;
}, 'int', []));
```

Need correct signature for each function.

Safer first approach: only log, not replace.

### D. Hook JNI APIs

Since `sub_4E354` uses JNI vtable heavily:

- `FindClass`
- `GetMethodID`
- `GetStaticMethodID`
- `CallObjectMethod`
- `RegisterNatives`
- `ThrowNew`

Hooking JNI calls can reveal hidden class/method names after string decode.

### E. Decode local strings around `0x897xx`

`sub_4E354` references data around:

```text
0x8972c
0x89738
0x8973c
0x89744
0x8976c
0x89770
0x89799
```

Some are flags/bytes, some are encrypted/obfuscated strings.

Relevant string/decode helpers seen:

```text
0x15D88
0x15DD4
0x15E24
0x3CF84
0x3DDB8
0x3E038
0x401B0
```

### F. Create IDA loader/analysis script

Automate:

1. load raw image base 0,
2. create code/function at init/fini entries,
3. define dynamic table structs,
4. label DT_NEEDED/STRTAB/SYMTAB/RELA/RELR,
5. label hidden entry `hidden_JNI_OnLoad` at `0x4e354`.

### G. Rebuild a pseudo-ELF

Optional but useful: use dynamic table and raw image to construct a minimal ELF wrapper so IDA/Ghidra can analyze better.

Need infer/load segments:

```text
text/data raw image size 0x90000
base 0
entry maybe 0x4e354
PT_DYNAMIC 0x84960
```

---

## 23. Most important offsets cheat sheet

### Outer `libdexprotector.so`

```text
0x378   constructor sub_378
0x440   exported JNI_OnLoad
0x748   strrchr-like, finds last char
0x918   derive unpack key
0xD4C   cipher ctx zero
0xD60   cipher set key
0xDAC   stream xor crypt
0x1290  unpack payload
0x167C  custom linker / reloc fixer
0x1C5C  LZ4 decompressor
0x2220  find auxv from /proc/self/stat
0x2358  find r_debug from auxv/main dynamic
0x2434  unpack+link+init, returns hidden entry
0x25B8  small string decryptor
```

### Unpacked image offsets

```text
0x200    SYMTAB
0x51c    STRTAB
0x6b8    RELR
0x800    JMPREL
0x84920  INIT_ARRAY
0x84958  FINI_ARRAY
0x84960  DYNAMIC
0x84bc8  PLTGOT
0x4e354  hidden JNI entry / returned by sub_2434
0x4e7d8  likely MessageGuardException throw/error handler
```

### Init array

```text
0x7c380
0x7c850
0x3ce5c
0x37ff8
0x40194
0x552f8
0x4eb60
```

---

## 24. `sub_374A0` and `sub_367A8` JNI setup

### `sub_374A0(JNIEnv *env)`

Not `RegisterNatives`. It is a JNI reference/cache initializer.

It decodes hidden class/method/field names with `sub_401B0` / `sub_55610`, calls JNI APIs, checks `ExceptionCheck` after most calls, and stores global refs / IDs into globals such as:

```text
qword_8CA30
qword_8C9F8
qword_8CA18
qword_8CA48
qword_8CA40
qword_8CA08
qword_8CA50
qword_8CA10
qword_8CA58
```

JNI table offsets identified:

```text
0x30   FindClass
0xA8   NewGlobalRef
0xF8   GetObjectClass
0x108  GetMethodID
0x110  CallObjectMethod
0x2F0  GetFieldID
0x2F8  GetObjectField
0x388  GetStaticMethodID
0x390  CallStaticObjectMethod
0x480  GetStaticFieldID
0x488  GetStaticObjectField
0x538  NewStringUTF
0x6B8  RegisterNatives
0x720  ExceptionCheck
```

`sub_374A0` does not use `RegisterNatives` (`JNIEnv+0x6B8` was not observed).

### `sub_367A8(JNIEnv *env)`

Runtime hook script used:

```text
hook_sub_367A8_jni_calls_frida17.js
```

Observed JNI calls show `sub_367A8` manipulates Android framework startup state around ContentProviders.

Observed log summary:

```text
obj=0x3186 likely ActivityThread.AppBindData
field providers Ljava/util/List;
providers = appBindData.providers
providers.isEmpty() -> false
NewGlobalRef(providers) -> saved global provider list
appBindData.providers = null
field restrictedBackupMode Z -> false
class 0x3146 likely android.app.ActivityThread
field mInitialApplication Landroid/app/Application;
method installContentProviders(Context,List)V
activityThread.mInitialApplication = applicationObject
```

Meaning:

```java
AppBindData data = ...;
List providers = data.providers;

if (providers != null && !providers.isEmpty()) {
    savedProviders = NewGlobalRef(providers);   // qword_8CA28
}

data.providers = null;                         // prevent framework auto-install now
restrictedBackupMode = data.restrictedBackupMode;

ActivityThread at = ...;
Application app = ...;

at.mInitialApplication = app;

cache:
  ActivityThread.mInitialApplication
  ActivityThread.installContentProviders(Context, List)
```

Why protector does this:

```text
Android ContentProviders normally run before Application.onCreate().
DexProtector wants no app/provider code to execute before unpack/decrypt/classloader/env-check setup is complete.
So it steals the providers list, clears AppBindData.providers, finishes protector initialization,
and later can manually call ActivityThread.installContentProviders(context, savedProviders).
```

Short name:

```c
sub_367A8 = init_delay_content_providers_and_cache_activitythread_fields
```

---

## 25. Recent decoded helpers / small utility funcs

### `sub_401B0` quick decoder facts

`sub_401B0(blob, out, len)` is the common small string decoder.
It is not a normal C string pointer input; the input points to a blob:

```text
blob+0  u32 state_a
blob+4  u32 state_b
blob+8  ciphertext bytes
```

The keystream is generated from the 0x6c-byte table copied to `qword_8CB40` by init `0x40194`.
That table is generated by init `0x37FF8` from seed `0x89160`.

Verified table:

```text
61d5ccc1cc0659b29b30e842f6fab3bd15edef6db465bf039775912d6e499aa20942d5d627bcafb8382f0055894fc3797529cb2ce6ec025423c8c33f6fd8b88065f72dca2a77a28a86a432549aab97cfa325cea8c96bbe3c0430df004b234a70dde895c6bd53d420909ae98a
```

Useful decoded examples:

```text
sub_401B0(dword_4143, out, 15)      -> "/proc/self/exe"
sub_401B0(dword_3991, out, 8)       -> "libc.so"
sub_401B0(dword_3406, out, 22)      -> "__system_property_get"
sub_401B0(dword_2DCF, out, 21)      -> "ro.build.version.sdk"
sub_401B0(&loc_52E4, out, 27)       -> "ro.product.first_api_level"
```

IDA may label a data blob as `loc_52E4`; here it is data, not real code.

Helper script:

```text
ida_comment_decode_calls.py
```

Scans all direct `BL decode/sub_401B0` call sites, statically resolves common `X0=blob` and `W2=len` setup patterns, decodes the string, and writes comments at the call site and blob address. It also handles simple shared jump-table decode call sites by checking predecessor branches.

### `sub_1529C`

`sub_1529C(a1, a2, a3)` is a `strtoull`-like parser, not decrypt/decode.

Likely prototype:

```c
uint64_t strtoull_like(const char *s, char **endptr, unsigned int base);
```

Behavior:

```text
- accepts base 0 or 2..36; rejects base 1 / base > 36
- skips ASCII whitespace
- accepts optional '+' / '-'
- base 0 auto-detects:
    0x / 0X -> base 16
    leading 0 -> base 8
    otherwise -> base 10
- parses 0-9/a-z/A-Z digits
- overflow saturates to UINT64_MAX
- if endptr != NULL, stores pointer to first unparsed char
```

### SDK range check

This pattern:

```c
if ((uint64_t)(sdk_ver - 1) > 0xFE)
    return 13;
```

means:

```c
if (sdk_ver < 1 || sdk_ver > 255)
    return 13;
```

The unsigned cast makes `sdk_ver == 0` underflow to `UINT64_MAX`, so it also fails.

---

## 26. More recent runtime helpers and r_debug lookups

### `sub_3B614`: manual `dlsym` via `r_debug`

`sub_3B614(lib_name, symbol_name)` walks the dynamic linker's `r_debug->r_map` list and resolves a symbol manually.

High-level behavior:

```c
r_debug = sub_3C3F0();
for (link_map *lm = r_debug->r_map; lm; lm = lm->l_next) {
    // lm->l_addr = load bias
    // lm->l_name = mapped library path
    // lm->l_ld   = dynamic section
    if (library_name_matches(lm->l_name, lib_name)) {
        parse_dynamic(lm->l_ld, lm->l_addr);
        return find_symbol_runtime_address(symbol_name);
    }
}
return 0;
```

If `lib_name` begins with `/`, it compares full path. Otherwise it compares basename of `lm->l_name`.

Confirmed decode around caller `sub_363F0`:

```c
v0 = sub_401B0(dword_3991, out, 8);   // "libc.so"
v1 = sub_401B0(dword_3406, out, 22);  // "__system_property_get"
v2 = sub_3B614(v0, v1);               // resolve libc __system_property_get
v4 = sub_401B0(dword_2DCF, out, 21);  // "ro.build.version.sdk"
v2(v4, buf);                          // read Android SDK property
sdk_ver = atoi/strtoull_like(buf);
```

Suggested name:

```c
sub_3B614 = manual_dlsym_from_r_debug
```

Related scripts:

```text
hook_sub_363F0_decode_v0_v1_frida17.js
ida_rename_sub_3B614.py
```

### `sub_3C3FC`: second way to find `r_debug`

`sub_3C3FC()` finds the linker `r_debug` pointer by reading the main executable ELF and process maps, instead of walking auxv like outer `sub_2358`.

Observed runtime flow:

```text
sub_401B0(dword_4143, out, 15) -> "/proc/self/exe"
readlinkat(AT_FDCWD, "/proc/self/exe", ...) -> "/system/bin/app_process64"
openat(AT_FDCWD, "/system/bin/app_process64", O_RDONLY)
read ELF header
lseek to program header table
read program headers
find PT_LOAD and PT_DYNAMIC
use /proc/self/maps helper sub_3C218 to compute runtime base
scan dynamic section for DT_DEBUG
store qword_8CB10 = DT_DEBUG value = r_debug pointer
```

Difference from outer `libdexprotector.so`:

```text
outer sub_2220/sub_2358:
  /proc/self/stat -> stack -> auxv -> main dynamic -> DT_DEBUG -> r_debug

hidden sub_3C3FC:
  /proc/self/exe -> app_process64 file -> ELF phdr -> maps base -> dynamic -> DT_DEBUG -> r_debug
```

Result is still the address of `struct r_debug`.

Related scripts:

```text
hook_sub_3C3FC_fileio_frida17.js       // old inline SVC version; can crash after success
hook_sub_3C3FC_fileio_safe_frida17.js  // safer probe/log version
```

### Generic unpacked-function hook helper

Script:

```text
hook_unpacked_fn_args_ret_frida17.js
bypass_dex_frida17.js
```

Purpose: hook an unpacked-image function by RVA and print args/return value.
Run with Frida parameters, for example:

```text
-P '{"offset":"0x3B614","argc":2}'
```

It waits for the hidden image load bias from outer linker flow, then attaches to `load_bias + offset`.

### Simple IDA paste/file decoder

Script file now available:

```text
ida_decode_sub_401B0.py
ida_comment_decode_calls.py
```

This is the simple pasteable IDAPython decoder for `sub_401B0` blobs. Edit only:

```python
BLOB_EA = 0x2DCF
LENGTH  = 21
```

Then run in IDA's Python script window. It prints decoded text and hex.

### `bypass_dex_frida17.js`

Current bypass script for this stage. It does two targeted hooks in the unpacked image:

```text
sub_16190 called from sub_4E354+0x294:
  return qword_8CEF8 so the integrity SipHash compare passes.

sub_15DD4 called from sub_4E354+0x2E0:
  force v52 output bytes to 8f f9 a6 be so the magic branch at 0x4E688 is skipped.
```

Run:

```bash
./frida17/bin/frida -U -f com.dexprotector.detector.envchecks -l bypass_dex_frida17.js
```

---

## 27. Mental model

Outer loader:

```text
libdexprotector.so = small unpacker + custom linker
```

Hidden payload:

```text
unpacked_image_0x90000.bin = raw in-memory libdp.so image
```

`sub_1290`:

```text
put furniture into house
```

`sub_167C`:

```text
connect wires: imports, relocations, pointers
```

`sub_2434`:

```text
finish setup, run constructors, return real JNI entry
```

`sub_4E354`:

```text
real protected native init/check logic
```

Current next battle:

```text
Find which check inside sub_4E354 returns nonzero and causes MessageGuardException.
```

---

---

## 28. `sub_3B4DC`, cached app path/package getters

### `sub_3B4DC(link_map, fnName)`

`sub_3B4DC` resolves a symbol from a **specific already-selected `link_map`**. It does not search the library name itself.

Prototype-like:

```c
void *resolve_symbol_from_link_map(struct link_map *lm, const char *symbol_name);
```

Observed logic:

```c
ctx[128];
if (parse_dynamic(ctx, lm->l_ld, lm->l_addr))
    return lookup_symbol(ctx, symbol_name);
return NULL;
```

`link_map` fields used:

```text
lm[0] = l_addr  // load bias / base
lm[1] = l_name  // library path/name
lm[2] = l_ld    // dynamic section
lm[3] = l_next  // next loaded lib
```

Difference from `sub_3B614`:

```text
sub_3B614(libName, fnName)
  walks r_debug->r_map to find libName first, then resolves fnName.

sub_3B4DC(link_map, fnName)
  assumes the target library link_map is already known, then resolves fnName.
```

Suggested names:

```c
sub_3B614 = manual_dlsym_from_r_debug
sub_3B4DC = resolve_symbol_from_link_map
sub_3AF24 = parse_elf_dynamic_for_symbol_lookup
sub_3B238 = lookup_symbol_in_dynamic_context
```

### Cached path/package getters

These are tiny getters over values cached earlier by `sub_374A0` from `ActivityThread.mBoundApplication.info` / `LoadedApk`.

```asm
sub_3747C:
  ADRP X8, qword_8CA50
  LDR  X0, [X8, qword_8CA50]
  RET

sub_37494:
  ADRP X8, qword_8CA10
  LDR  X0, [X8, qword_8CA10]
  RET
```

Meanings:

```c
char *sub_3747C(void) { return qword_8CA50; } // LoadedApk.mAppDir
char *sub_37494(void) { return qword_8CA10; } // LoadedApk.mPackageName
```

Earlier cache source in `sub_374A0`:

```text
qword_8CA50 = strdup(LoadedApk.mAppDir)
qword_8CA10 = strdup(LoadedApk.mPackageName)
qword_8CA58 = strdup(LoadedApk.mDataDir)
```

So in `sub_4E354`:

```c
v48 = sub_3747C(v47);  // v48 = app APK/source dir path, from LoadedApk.mAppDir
v49 = sub_37494();     // v49 = package name, e.g. com.dexprotector.detector.envchecks
```

---

## 29. `sub_59F40`: APK/source path + AssetManager consistency check

`sub_59F40` is called from the hidden JNI entry `sub_4E354` after cached Java/Android objects are ready.

Call shape in `sub_4E354`:

```c
appDir  = sub_3747C();   // qword_8CA50 = LoadedApk.mAppDir / APK source path
pkgName = sub_37494();   // qword_8CA10 = LoadedApk.mPackageName
ret = sub_59F40(appDir, pkgName, AAssetManager_ptr);
```

Meaning:

```c
int check_apk_asset_consistency(const char *appDir,
                                const char *packageName,
                                AAssetManager *amgr);
```

### Main purpose

This is an anti-tamper / anti-repack check. It verifies that:

1. `LoadedApk.mAppDir` looks like a valid APK/source path.
2. For `/data/app`, `/mnt/expand`, `/mnt/asec`, the path contains `"/<packageName>-"`.
3. The APK path matches the real target of `/proc/self/fd/<apk_fd>`.
4. The file/inode behind the APK fd matches the path passed from Java state.
5. `AAssetManager` can open a protected asset from the same APK file.

Suggested rename:

```c
sub_59F40 = check_apk_asset_consistency
```

### Path prefix checks

Decoded prefixes used by `sub_59F40`:

```text
/data/app/
/mnt/expand/
/mnt/asec/
/vendor/
/system/
/preload/
```

For data-app style paths, it builds:

```c
needle = "/" + packageName + "-";
```

Example:

```text
/com.dexprotector.detector.envchecks-
```

Then it requires:

```c
strstr(appDir, needle) != NULL
```

If not found, return code is `118`.

### `sub_5A4C8(appDir)` helper

Suggested rename:

```c
sub_5A4C8 = verify_app_fd_path_inode
```

What it does:

```text
- get protected/app APK fd from internal state: *(int *)(sub_366B4() + 28)
- fstat(fd)
- build "/proc/self/fd/<fd>"
- readlinkat(AT_FDCWD, "/proc/self/fd/<fd>", ...)
- stat(real_fd_target)
- compare device/inode from fstat vs stat
- compare appDir string vs real fd target path
```

So it detects fake `LoadedApk.mAppDir`, fd swapping, or APK path mismatch.

### `sub_5A640(AAssetManager*)` helper

Suggested rename:

```c
sub_5A640 = verify_asset_manager_uses_same_apk_fd
```

What it does:

```text
- find libandroid.so link_map via sub_3B590("libandroid.so")
- resolve symbols from that link_map using sub_3B4DC:
  - AAssetManager_open
  - AAsset_openFileDescriptor
  - AAsset_close
- decode protected asset name using sub_55610
- open that asset through AAssetManager
- get asset fd with AAsset_openFileDescriptor
- fstat(asset_fd)
- fstat(main_apk_fd)
- compare device/inode
```

So it checks that Java `AssetManager` is really backed by the same APK/source file as the app fd.

### Return codes observed

```text
0    OK
108  appDir too short
109  invalid/unknown source path prefix
110  failed/too long package needle build
111  /proc/self/fd or stat/fstat consistency check failed
112  appDir string != real /proc/self/fd/<apk_fd> target
114  AAssetManager_open failed
115  AAsset_openFileDescriptor failed
117  asset fd is not from same APK inode/device
118  data-app style path does not contain "/<packageName>-"
122  libandroid.so link_map not found
123  AAsset* symbol resolution failed
```


---

## 30. `sub_3601C` / `sub_3662C` block in `sub_4E354`

Code in hidden JNI entry:

```c
v28 = sub_3601C();
inited = v28;
if (!(_DWORD)v28) {
    v29 = sub_3747C(v28);
    inited = sub_3662C(v29);
}
```

Meaning:

```c
ret = init_runtime_version_offsets();
if (ret == 0) {
    appDir = get_cached_loaded_apk_app_dir();
    ret = open_and_parse_app_apk_zip(appDir);
}
```

### `sub_3601C` = initialize runtime-version dependent offsets

Suggested rename:

```c
sub_3601C = init_runtime_art_dalvik_offsets
```

It reads the Android SDK/runtime version from `dword_8C9E0` via `sub_36600()` and initializes global offsets:

```text
qword_8C9B0
qword_8C9B8
qword_8C9C0
qword_8C9D8
off_8C9D0
```

For old Android / Dalvik path, `sdk <= 20`:

```c
qword_8C9B8 = 0x20;
off_8C9D0 = manual_dlsym_from_r_debug("libdvm.so", "_Z15dvmUseJNIBridgeP6MethodPv");
return off_8C9D0 ? 0 : 2;
```

For ART path, `sdk > 20`, it does not resolve `libdvm.so`. Instead it fills those globals with different offsets depending on SDK version. These are likely offsets into Android runtime internal structures such as `ArtMethod` / JNI bridge / entrypoint fields. They are version-specific because ART layout changes across Android releases.

Return:

```text
0  OK
2  old Dalvik path failed to resolve dvmUseJNIBridge
```

### `sub_3747C` = getter for cached APK path

Disassembly:

```asm
ADRP X8, qword_8CA50
LDR  X0, [X8, qword_8CA50]
RET
```

Suggested rename:

```c
sub_3747C = get_cached_loaded_apk_app_dir
```

It returns `qword_8CA50`, cached earlier by `sub_374A0` from `LoadedApk.mAppDir` / APK source path.

### `sub_3662C(appDir)` = open and parse APK as ZIP

Suggested rename:

```c
sub_3662C = init_app_apk_zip_info
```

It allocates `0x20` bytes, then calls `sub_3C640(out, appDir)`.

`sub_3C640` does:

```text
openat(AT_FDCWD, appDir, O_RDONLY)
fstat(fd)
mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0)
scan backward for ZIP EOCD signature 0x06054b50
read central-directory offset / size / entry count
store APK ZIP metadata into the 0x20-byte struct
```

Struct layout written by `sub_3C640`:

```c
struct ApkZipInfo {
    void    *mmap_base;      // +0x00
    uint64_t file_size;      // +0x08
    uint32_t cd_offset;      // +0x10
    uint32_t cd_end;         // +0x14 = cd_offset + cd_size
    uint32_t entry_count;    // +0x18
    int      fd;             // +0x1c
};
```

On success:

```c
qword_8C9E8 = apk_zip_info;
return 0;
```

On failure:

```text
malloc failed -> 20
ZIP/open/parse failed -> log/report code 9 + detail, then return 21
```

### Why this block exists

This block prepares two things for later checks:

1. Runtime layout offsets for ART/Dalvik-specific native/JNI checks.
2. A memory-mapped view of the real app APK plus ZIP central-directory metadata.

Later functions use this APK metadata for asset/APK integrity checks, including `sub_59F40` and `sub_5E684` / `ic.dat` verification.

---

## 31. `sub_15D88(&unk_89799, 32, &byte_8972C, 64, v54)`

Call in `sub_4E354`:

```c
sub_15D88(&unk_89799, 32LL, &byte_8972C, 64LL, v54);
```

Wrapper logic:

```c
uint64_t sub_15D88(void *key, size_t key_len,
                   void *msg, size_t msg_len,
                   void *out32)
{
    desc = sub_29248(9);          // hash/PRF descriptor: alg id 9, digest 0x20, block 0x40
    return sub_28AB4(desc, key, key_len, msg, msg_len, out32);
}
```

`sub_28AB4/sub_29B54` implement an HMAC-like PRF using descriptor id `9`, i.e. SHA-256-like:

```c
out32 = HMAC_SHA256(key=unk_89799[0:32], msg=byte_8972C[0:64]);
```

Static inputs from the unpacked image:

```text
unk_89799[32]
0247ac85e40b5de63c46ea3c5196a2f1c20c437bbda49fab0d09b5a90b8e1688

byte_8972C[64]
19afcbddc54d38e11f9f32c6d1e407434ecdc0af5a4ef612dd2b0ec92e4899fa9eec8cdb87aff11d0c8801e2c9910d4ad9143f05563844257c5140254a9f58d8
```

Expected output immediately after `sub_15D88` if those static inputs are unchanged:

```text
v54[32] = 68daae1f35ace64a551d7c5e7f293b5af12d8700c767c30854fd0c0155576f0c
```

Side effects:

```text
- Writes 32 bytes to output buffer v54.
- Does not mutate unk_89799.
- Does not mutate byte_8972C.
- Allocates temporary hash/HMAC state internally, then wipes/frees it via sub_29278.
```

Important: this is only the initial crypto/check context. Immediately after this call, `sub_4E354` may further mutate `v54` with:

```c
if (byte_8972C & 1) sub_3CF84(v54);
if (!(byte_8973C & 1)) sub_3DDB8(v54, value_from_byte_89770_73);
sub_3E038(v54);
```

So `v54` after `sub_15D88` is not the final ctx/key used by `ic.dat`.

---

## 32. `sub_3CF84(v54)`

Called in `sub_4E354` only when:

```c
if (byte_8972C & 1)
    sub_3CF84(v54);
```

For this sample `byte_8972C[0] = 0x19`, so bit0 is set and this function runs.

Suggested rename:

```c
sub_3CF84 = mix_apk_signature_into_crypto_context
```

### High-level purpose

`sub_3CF84` mutates the 32-byte crypto/check context `v54` using information from the app APK signature. It ties the later key/context to the exact APK signing material.

Input APK metadata comes from:

```c
apkInfo = sub_366B4(); // qword_8C9E8 from sub_3662C/open_and_parse_app_apk_zip
```

`apkInfo` contains APK mmap pointer, file size, central directory offset/end, entry count, fd.

### Main control flow

```c
void sub_3CF84(uint8_t ctx[32]) {
    apkInfo = qword_8C9E8;

    if (apkInfo->entry_count < 4)
        return; // ctx unchanged

    if (sdk < 24)
        return fallback_scan_META_INF_and_mix(ctx, apkInfo);

    if (find_apk_signing_block_42(apkInfo, &sigBlock, &sigBlockSize) != 0)
        return fallback_scan_META_INF_and_mix(ctx, apkInfo);

    // Android P / API 28+ prefers APK Signature Scheme v3.
    if (sdk >= 28 && mix_signing_scheme_block(ctx, sigBlock, sigBlockSize, 0xF05368C0))
        return;

    // Otherwise try APK Signature Scheme v2.
    if (mix_signing_scheme_block(ctx, sigBlock, sigBlockSize, 0x7109871A))
        return;

    fallback_scan_META_INF_and_mix(ctx, apkInfo);
}
```

Important IDs:

```text
0x7109871A = APK Signature Scheme v2 block id
0xF05368C0 = APK Signature Scheme v3 block id
```

`sub_3CAA0` finds the APK Signing Block by checking the footer magic:

```text
"APK Sig Block 42"
```

### How `v54` changes

`v54` is a 32-byte context. `sub_3CF84` does not simply XOR it. It repeatedly calls:

```c
sub_15E24(ctx, data, data_len, ctx);
```

`sub_15E24` means roughly:

```c
tmp = PRF_SHA256(ctx, constant_0x07FFCFC433E03432, 32);
ctx = HMAC_SHA256(key=tmp, msg=data);
```

So every call to `sub_15E24` overwrites all 32 bytes of `v54` with a new derived value.

### If v2/v3 signing block is found: `sub_3D034`

`sub_3D034(ctx, sigBlock, sigBlockSize, blockId)`:

1. Finds the v2/v3 block inside APK Signing Block.
2. Parses signer/certificate/digest records.
3. Computes SHA-256 hashes over selected signature/cert data using `sub_320B4`.
4. Sorts 32-byte hashes with `sub_3DB90`.
5. Computes a combined 32-byte digest `v29`.
6. Mixes static table and matching derived values into `ctx`:

```c
sub_15E24(ctx, &unk_89452, 240, ctx);

for each 40-byte marker in:
    unk_89452
    unk_8947A
    unk_894A2
    unk_894CA
    unk_894F2
    unk_8951A
{
    if (sub_160FC(v29, marker, 40, tmp32, 32) == 0)
        sub_15E24(ctx, tmp32, 32, ctx);
}
```

Return `1` means it found and processed the requested signing block. Return `0` means not found/invalid.

### Fallback path: `sub_3D47C`

If APK Signing Block is missing/invalid, or v2/v3 data cannot be used, `sub_3D47C` scans ZIP central-directory entries under:

```text
META-INF/
```

It looks for signature/certificate-style files such as `.RSA`, `.DSA`, `.EC`, `.SF`, hashes/decompresses relevant entries, then performs a similar `sub_15E24` mixing sequence.

### Side effects

Persistent side effect:

```text
v54[0:32] is overwritten one or more times.
```

No persistent mutation expected for:

```text
unk_89799
byte_8972C
APK mmap contents
qword_8C9E8
```

Temporary buffers are wiped locally.

### Why this matters

After `sub_15D88`, `v54` is purely static-derived. After `sub_3CF84`, `v54` becomes APK-signature-derived. If APK signing data differs, or if this function is skipped/spoofed incorrectly, later checks fail:

```text
sub_15DD4 magic check may output wrong 4 bytes
sub_5E684 ic.dat decrypt/auth can fail with 714
```

### Practical note: effect of repacking

For `sub_3CF84`, if the APK is the original/unmodified package and is not repacked/resigned, this step should be stable and should not cause failure by itself.

Reason:

```text
sub_3CF84 derives/mixes v54 from the APK signing material.
Original APK signing block / META-INF signature data unchanged => same derived v54.
```

If the app is repacked or resigned, the APK Signature Scheme v2/v3 block or `META-INF/*` signature files change. Then `sub_3CF84` derives a different `v54`, causing later checks to fail, commonly:

```text
sub_15DD4 magic mismatch
sub_5E684 / ic.dat decrypt-auth fail, e.g. 714
APK/asset integrity mismatch
```

So for dynamic Frida analysis on the original installed APK, `sub_3CF84` itself is usually safe. The bigger risk is not repacking, but Frida hooks that patch code pages before later context derivation such as `sub_3E038`.

---

## 33. `sub_3DDB8(v54, 1)`

Called in `sub_4E354` after `sub_3CF84` only when:

```c
if (!(byte_8973C & 1)) {
    uint32_t n = byte_89770 | byte_89771 << 8 | byte_89772 << 16 | byte_89773 << 24;
    sub_3DDB8(v54, n);
}
```

For this sample:

```text
byte_8973C = 0x4e  => bit0 clear, so the call runs
byte_89770..73 = 01 00 00 00 => n = 1
```

So actual call is:

```c
sub_3DDB8(v54, 1);
```

Suggested rename:

```c
sub_3DDB8 = mix_dex_file_content_into_crypto_context
sub_3DF04 = mix_zip_entry_prefix_into_crypto_context
```

### High-level purpose

This step mutates the 32-byte context `v54` using APK DEX file content.

It gets APK ZIP metadata from:

```c
apkInfo = sub_366B4(); // qword_8C9E8
```

Then it tries to process:

```text
classes.dex
classes2.dex
classes3.dex
...
classesN.dex
```

where `N` is the second argument.

In our case `N = 1`, so only this is processed:

```text
classes.dex
```

### Flow

```c
bool ok = sub_3DF04(v54, apkInfo, "classes.dex");

if (!ok) {
    sub_15E24(v54, "1", 1, v54);
    return;
}

for (i = 2; i <= N; i++) {
    name = "classes" + i + ".dex";
    if (!sub_3DF04(v54, apkInfo, name))
        break;
}
```

Because `N = 1`, the loop for `classes2.dex` is skipped.

### What `sub_3DF04` mixes

`sub_3DF04(ctx, apkInfo, zipEntryName)`:

1. Finds the ZIP central-directory entry by name.
2. Resolves the local file data pointer.
3. If entry is compressed with ZIP method 8 / deflate:
   - decompresses up to first `min(uncompressed_size, 0x400)` bytes.
   - mixes those bytes into `ctx`.
4. If entry is stored/uncompressed:
   - mixes first `min(size, 0x400)` bytes directly.
5. If lookup/decompress fails:
   - mixes single byte ASCII `'1'` into `ctx`.

The mixing operation is again:

```c
sub_15E24(ctx, data, data_len, ctx);
```

Meaning `v54[0:32]` is overwritten with a new derived 32-byte value.

### Side effects

Persistent side effect:

```text
v54[0:32] changes.
```

No persistent change to:

```text
APK mmap
qword_8C9E8
byte_89770..73
byte_8973C
```

### Practical meaning

This binds the crypto/check context to the DEX content in the APK. If `classes.dex` changes because the app is repacked/rebuilt, then `v54` changes and later checks can fail.

For original APK without repacking, this step should be deterministic and stable.

---

## 34. `sub_3E038(v54)`

Called after the static/APK-signature/DEX-content context mixing:

```c
sub_3E038(v54);
```

Suggested rename:

```c
sub_3E038 = mix_hidden_native_image_integrity_into_crypto_context
```

### What it checks

This function checks / fingerprints the unpacked hidden native image in memory, not the Java APK repack state.

It starts from the 16KB page containing `loc_3E064`:

```c
page = align_down(&loc_3E064, 0x4000); // hidden_base + 0x3c000 in this sample
```

Then scans backward by `0x4000` bytes until it finds the custom image header:

```text
header[0..3] == 00 00 00 00
header[0x0b] == 0x0b
header[0x3f] == 0x0e
```

In our dumped hidden image this header is at:

```text
hidden_base + 0x0
```

The header encodes a protected length using weird byte positions:

```c
protected_len = header[0x17] | header[0x1d] << 8 | header[0x25] << 16;
```

For this sample:

```text
protected_len = 0x7caa0
```

Then it computes a 32-byte digest over:

```text
hidden_base + 0x0 ... hidden_base + 0x7caa0
```

using `sub_320B4`.

### How it mutates `v54`

After digesting the hidden image region into `v8[32]`, it calls:

```c
sub_160FC(v8, &unk_89543, 40, tmp32, 32)
```

Static blob:

```text
unk_89543[40] =
0f9f4d727950837d81b7cf2231e275c7076a1879d0db0a398343d03261f3c8224c4102edfb4f40ac
```

If `sub_160FC` succeeds:

```c
sub_15E24(v54, tmp32, 32, v54);
```

So the persistent effect is:

```text
v54[0:32] is overwritten with a new derived value based on hidden native image bytes.
```

If the custom header is not found, it falls back to mixing byte ASCII `'z'`:

```c
sub_15E24(v54, "z", 1, v54);
```

If `sub_160FC` fails, it wipes temp buffers and logs/report code `12` via `sub_656C0(12)`.

### Why this matters for Frida

Unlike `sub_3CF84` and `sub_3DDB8`, this is not about APK repack/signature. It hashes the unpacked native image currently mapped in process memory.

Therefore hooks installed before `sub_3E038` can affect the digest if Frida patches any instruction inside:

```text
hidden_base + 0x0 .. hidden_base + 0x7caa0
```

This includes most hidden functions and the `sub_4E354` callsites. If those bytes differ, the derived `v54` can differ, causing later failures such as:

```text
sub_15DD4 magic mismatch
sub_5E684 ic.dat decrypt-auth fail 714
```

Practical rule:

```text
Before sub_3E038: avoid patching/hooking inside hidden_base+0x0..0x7caa0.
After sub_3E038: safer to install hooks needed for dumping/decrypt tracing.
```

---

## 35. Runtime-clean hash bypass result: `sub_3E038`, `sub_16190`, `sub_15DD4`, `ic.dat`

Latest working observation:

```text
runtime clean sub_3E038 digest =
fce5f155a916bccade80a9c585c98f55064e0918095592ad4754aea5932a8696
```

This digest must be computed at runtime after hidden image is executable, right before outer JNI_OnLoad calls hidden entry:

```asm
outer libdexprotector.so+0x464  LDR X8, [X19,#0x230]   ; hidden entry = hidden_base+0x4E354
outer libdexprotector.so+0x468  BLR X8
```

Computing at `sub_167C onLeave` was too early:

```text
compute failed: access violation accessing hidden+0x320b4
```

At `outer JNI_OnLoad+0x468`, calling hidden `sub_320B4(hidden_base, 0x7caa0, out, 0)` works and gives the correct runtime digest. Static file hash from `dumps/unpacked_image_relocated_hybrid.bin[0:0x7caa0]` was wrong for this check.

Then the one-shot `sub_320B4` hook inside `sub_3E038` forces that runtime-clean digest:

```text
[sub_320B4/sub_3E038 force digest]
clean=fce5f155a916bccade80a9c585c98f55064e0918095592ad4754aea5932a8696
source=runtime-clean
```

`sub_160FC` accepts this digest. `sub_3E038` no longer returns error code `0xc`.

---

### Clean `sub_16190` hash

At the same clean point, compute:

```c
sub_16190(hidden_base + 0x10E00, 0x663E8, zero_key16)
```

Observed clean hash:

```text
runtime clean sub_16190 hash = 0xfc920bfb67d0075a
```

This matches runtime `qword_8CEF8`:

```text
qword_8CEF8 = 0xfc920bfb67d0075a
```

Mid-block hook at `0x4E5E8` was fragile and caused crashes. Better method:

1. Precompute clean `sub_16190` hash before hidden hooks.
2. Hook `sub_16190` function entry after hidden hooks.
3. Only spoof the protected-code call:

```text
args:
  data = hidden_base + 0x10E00
  len  = 0x663E8
  key  = zero16 stack key
return:
  0xfc920bfb67d0075a
```

Observed:

```text
[sub_16190 spoof protected]
real=0xd895851a9f63e78e -> 0xfc920bfb67d0075a
```

This avoids the poison path:

```c
sub_15E24(v54, "\0", 1, v54);
```

---

### `v54` now verified correct

With runtime-clean `sub_3E038` digest and protected-call `sub_16190` spoof, `sub_15DD4` does not need spoofing.

Observed:

```text
[sub_15DD4 actual]
v54=2fb0981db149168fce51e77f4a152d94b020089cd7c5f5b65bf3dc21a7b565d4
input=5994656b07fba491
out=8ff9a6be
expected=8ff9a6be
v54_ok=true
```

Conclusion:

```text
v54 is now correct before sub_15DD4.
```

`sub_15DD4` is only verifier/PRF output; it does not mutate `v54`.

---

### `ic.dat` decrypt/decompress result

With correct `v54`, `sub_5E684` successfully decrypts and decompresses `assets/ic.dat`.

Observed:

```text
[ic.dat decrypt leave] ret=0
[ic.dat decrypted] decomp_size=0xd2 comp_size=0x8b
[ic.dat decompress leave] written=0xd2 expected=0xd2
```

Dumped files on device:

```text
/data/data/com.dexprotector.detector.envchecks/files/ic_dat_dumps/ic_raw_encrypted_asset.bin
/data/data/com.dexprotector.detector.envchecks/files/ic_dat_dumps/ic_decrypted_with_size_and_compressed.bin
/data/data/com.dexprotector.detector.envchecks/files/ic_dat_dumps/ic_decrypted_compressed_payload.bin
/data/data/com.dexprotector.detector.envchecks/files/ic_dat_dumps/ic_decompressed.bin
```

Parsed `ic_decompressed.bin`:

```text
siphash_key16=d4278b9ed41c9d789b9120c2348f6f3a
expected_hash=3263391480026587514
entry_count=10
```

Listed entries:

```text
assets/chinook.db
assets/classes.dex.dat
assets/dp.arm-v7.so.dat
assets/dp.mp3
assets/dp_db.mp3
assets/ict.dat
assets/rcdb.dat
assets/resources.dat
assets/se.dat
classes.dex
```

Current remaining failure:

```text
[sub_5E684 leave] ret=0x2db (731)
```

Meaning:

```text
ic.dat decrypt/decompress passes, but later APK entry integrity/hash verification fails.
```

Next likely target:

```text
Reverse the post-decompress loop inside sub_5E684 that uses the decompressed entry list, CRC values, and siphash_key16. Bypass or satisfy final expected_hash compare.
```

## 2026-05-13 — `sub_5E684` / `ic.dat` CRC verification results

New CRC tracing was added to `hook_dump_ic_dat_frida17.js`:

- `sub_5E684`
  - logs CRC32 values read from APK ZIP central directory for entries listed in decrypted/decompressed `ic.dat`.
  - logs final SipHash compare over the CRC32 array.
- `sub_5F0D0`
  - logs path recovered from `qword_8CEF0 -> sub_4E348() -> sub_3C0EC(... /proc/self/maps ...)`.
  - logs native-lib CRC path if reached.
- `sub_5F46C`
  - logs real native-lib file path, expected CRC32, computed CRC32 from `sub_771EC()`.

Important fix: our Frida hook on hidden `sub_4E354` perturbs LR, so `qword_8CEF0` may be saved as a Frida/anonymous return address. `sub_5F0D0` then cannot recover the outer libdexprotector path and returns `731`. The script now restores:

```text
qword_8CEF0 = outer libdexprotector.so base + 0x46c
```

Observed after fix:

```text
[ic.dat parsed]
siphash_key16 = d4278b9ed41c9d789b9120c2348f6f3a
expected_hash = 0x2d49e542ca05617a
entry_count   = 10

CRC entries from APK central directory:
0 assets/chinook.db          crc=0xccf2ef83
1 assets/classes.dex.dat     crc=0x3e86695c
2 assets/dp.arm-v7.so.dat    crc=0x571bcdd6
3 assets/dp.mp3              crc=0x89858e35
4 assets/dp_db.mp3           crc=0x2a1c341b
5 assets/ict.dat             crc=0x313cfab9
6 assets/rcdb.dat            crc=0xd2ecba0e
7 assets/resources.dat       crc=0x88b8abe6
8 assets/se.dat              crc=0x8bf989a4
9 classes.dex                crc=0x5c81defc

SipHash over CRC array:
expected = 0x2d49e542ca05617a
computed = 0x2d49e542ca05617a
match    = true
```

Conclusion: `ic.dat` decrypt/decompress is correct, and the APK CRC/SipHash check inside `sub_5E684` passes.

`sub_5F0D0` behavior:

```text
[sub_5F0D0 path] ".../split_config.arm64_v8a.apk"
[sub_5F0D0 strlen] last4=".apk"
[sub_5F0D0 SUCCESS] returning 0
```

This is expected. If the mapped outer lib path ends with `.apk`, protector assumes the native library is loaded directly from the APK/split APK, so it skips native extracted-file CRC thread setup and returns success. The native-file CRC path (`sub_5F364 -> sub_5F46C`) is only used when the native lib path is an extracted `.so` file rather than an APK path.

Therefore current termination after this point is not caused by `sub_5E684`/`sub_5F0D0` failure. Next suspected phase is after returning to `sub_4E354`, especially final handoff:

```c
sub_4EB9C(env, v54, AAssetManager*)
```

Next hooks to add if needed:

- `sub_5E684` leave
- `sub_4EB9C` enter/leave
- `sub_4E7D8` MessageGuardException path
- libc/syscall exits: `exit`, `exit_group`, `abort`, `kill`, `tgkill`


## 2026-05-13 — `sub_4EB9C(env, v54, AAssetManager*)` final gate / Java bootstrap

`sub_4EB9C` is the phase immediately after `sub_5E684(v54)` succeeds. It is not the original unpacker. It is the final protector gate plus Java/bootstrap setup.

High-level shape:

```c
int sub_4EB9C(JNIEnv *env, uint8_t *v54, AAssetManager *am) {
    err = sub_58DF8();              // binder / service manager init
    if (!err) {
        pkg_err = sub_592A4(env);   // PackageManager transaction/method ids
        ks_err  = sub_59764(env);   // Keystore transaction ids
        err = ks_err ? ks_err : pkg_err;
    }

    if (err && err != 404) {
        sub_656C0(15);
        sub_656C0(0);
        sub_656EC(&err, 2);
        return err;
    }

    byte_8CEE8 = 1;                 // sensitive-check phase
    /* debugger/root/emulator/xposed/container/installer checks */
    byte_8CEE8 = 0;

    return sub_4EFB0(env, v54, am); // final Java payload/bootstrap
}
```

### First half: environment gates

| Call | Meaning |
|---|---|
| `sub_58DF8()` | Binder init: opens `/dev/binder`, checks binder version, mmaps binder buffer, resolves IServiceManager transaction ids. `404` is tolerated as non-fatal. |
| `sub_592A4(env)` | Resolve PackageManager methods/transactions: `getPackageInfo`, `getPackageUid`, `UserHandle.myUserId`. |
| `sub_59764(env)` | Resolve Keystore transaction ids: `getSecurityLevel` / old hardware-backed keystore checks. |
| `sub_5AFF8()` | `/proc/self/status` `TracerPid` check, installs `pthread_atfork`, spawns anti-debug monitor thread. |
| `sub_59B60(env)` | Java debugger check via `dalvik/system/VMDebug.isDebuggerConnected()`, plus anti-hook sanity. |
| `sub_5B59C()` | Misc environment check; returns `776` on detected condition. |
| `sub_652F8()` | Generic root/hooking check stage. |
| `sub_675E8(env, context)` | UID / app ownership / package path consistency checks. Also checks container-ish properties. |
| `sub_67E44(env)` | Xposed-style Java class checks. |
| `sub_5B5B8()` | Emulator/cloud/Raspberry property checks. |
| `sub_6531C()` | Installed root/Xposed/LuckyPatcher/Substrate/RootCloak style package checks. |
| `sub_5BA64(&flags)` | Custom ROM/property checks: Lineage, MIUI, YunOS, etc. Sets category flags. |
| `sub_67C08()` | Docker/container checks: `/.dockerenv` and related signals. |
| `sub_68738()` | Xposed package/file checks: installer, `XposedBridge.jar`, `xposed.prop`, `libxposed_*`. |
| `sub_5B740()` | Emulator file/proc checks: qemu, vbox, nox, goldfish, virtio, Memu, Redfinger, Raspberry. |
| `sub_6539C()` | Root binary/path checks: `su`, `daemonsu`, `supolicy`, `/su/su`, `PATH` search. |
| `sub_5F5A8(env, blob, flag, &flags)` | Optional attestation/timing/env check if corresponding config flags are enabled. |
| `sub_687B8()` | Drozer package check: `com.mwr.dz`. |
| `sub_66B78(env, context)` | Installer package check. Observed expected/interesting string: `com.google.android.packageinstaller`. |

Many failures call `sub_65B2C(mask)` to record category bits. Some are hard-fail depending on config flags; some are logged then ignored by zeroing the local error.

Important flag behavior in the current dump:

```text
byte_8973A bit0 = 1  debug checks strict
byte_89747 bit0 = 1  emulator checks strict
byte_89744 bit0 = 1  root/custom-ROM checks strict and optional extra gate
byte_8974A bit0 = 1  Xposed checks strict
byte_89748 bit0 = 0  installer check may be ignored after ExceptionCheck handling
byte_89746 bit0 = 0  final soft-detect gate behavior
```

### Second half: `sub_4EFB0(env, v54, assetManager)`

`sub_4EFB0` is the final bootstrap. It creates an `int[8]`, loads/decrypts a hidden Java class, lets Java fill that int array, mixes those 32 bytes into `v54`, then runs feature modules keyed from the updated `v54`.

Core flow:

```c
jintArray arr = env->NewIntArray(8);
err = sub_4F44C(env, arr);
if (err) return err;

raw32 = env->GetPrimitiveArrayCritical(arr, NULL); // int[8] = 32 bytes
sub_15E24(v54, raw32, 32, v54);                    // mix Java-provided material into v54
wipe(raw32_copy);

for each enabled feature flag:
    sub_15EC8(v54, out32, &constant64, 8);          // derive per-feature token
    err = feature_init(env, out32, ...);
    if (err) return err;
```

### `sub_4F44C(env, intArray)` hidden Java class loader

Observed decoded strings / behavior:

```text
static field name: "BHbHm"
static field sig : "[B"
hidden class     : "com/dexprotector/detector/envchecks/ProtectedApplication$ProtectedApplication"
method sig       : "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"
native name      : "AgqpckdwFG"
native sig       : "()[B"
static method    : "hcrnly"
static sig       : "([I)V"
```

`sub_4F44C` steps:

1. Finds static byte array field `BHbHm:[B` on a cached protector class.
2. Reads the byte array:
   - first 32 bytes = key/material,
   - remaining bytes = encrypted payload.
3. Derives a decrypt context with `sub_15F44(first32, 32, byte_8972C, 64, ctx)`.
4. Calls `sub_3E8E8(...)` to decrypt/load the hidden Java class.
5. Finds class `ProtectedApplication$ProtectedApplication`.
6. Finds method `h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;` (`unk_479F` currently decodes to `"h"`) and caches it via `sub_35F94`.
7. Registers native method `AgqpckdwFG()[B -> sub_4F87C`.
8. Finds static method `hcrnly([I)V` and calls it with the `int[8]` created by `sub_4EFB0`.

`sub_4F87C` returns a fixed 32-byte Java byte array:

```text
9fbf0eec3d806d8f074a6e441a415ceafb6578c75a816cc848198a9eb7add22d
```

This is likely one side of a native<->Java key handshake. The Java method then writes 8 ints back into `intArray`, and native folds those 32 bytes into `v54`.

### Feature modules called from `sub_4EFB0`

Each enabled module uses:

```c
sub_15EC8(v54, out32, &constant64, 8);
```

then passes `out32` to a feature init/check function.

Current dump flag state:

| Flag | Bit0 | Constant | Call | Meaning / guess |
|---|---:|---:|---|---|
| `byte_89730` | 1 | `0x873552BC11E8FF0E` | `sub_3EB6C(env,out32)` | Decrypt/load class chunks from asset id 5. Uses decoded asset-ish base `DF3FC58E29EAE0954C17E32FAEA140B4673FA808B877CB0E6F421373563DFC96` and suffix `/classesN`. |
| `byte_8972D` | 1 | `0xF9A939C6FCAE9717` | `sub_402E0(env,out32, byte_89738&1)` | Decrypt/decompress asset id 4, load class/payload, optionally do provider-related follow-up. |
| `byte_8973D` | 1 | `0xE196DE1BC97AB57A` | `sub_55718(env,out32)` | Init encrypted string table and register native `s(Ljava/lang/String;)Ljava/lang/String;`. |
| `byte_89745` | 1 | none | `sub_65B50(env)` | Setup `ProtectedApplication$ProtectedApplication$QrGen$Segment`, register native helpers, cache ctor/field refs. |
| `byte_89741` | 0 | `0x6F988B15B1F4EEF1` | `sub_66480(env,out32)` | Disabled in this dump. |
| `byte_8972E` | 1 | `0xE5CADA586D49689A` | `sub_51E4C(env, context, out32)` | Cache `Context.getAssets()`, `AssetManager.openNonAsset(String)`, `NullPointerException`, `Class.getName()`, register native `ylGi(Object,String):InputStream`. |
| `byte_89736` | 0 | `0x37265C912A43CDAC` | `sub_53B24(env,out32)` | Disabled in this dump. |
| `byte_8972F` | 1 | `0x9F5ADC9EE0B3913B` | `sub_53390(env,out32)` | Decrypt asset id 2 and initialize another runtime blob/global area. |
| `byte_89739` | 0 | `0xA68765019986F10B` | `sub_4FF68(env,out32)` | Disabled in this dump. |
| `byte_89737` | 0 | `0xEC1AAD7D6B3AA721` | `sub_56578(env,out32)` | Disabled in this dump. |
| `byte_89749`/`byte_89742` | 0/0 | `0x27673C669A996999` | `sub_3A6A0`, `sub_3A404(out32)` | Disabled in this dump. |
| always | - | none | `sub_51A10(env, assetManager)` | Cache native `AAssetManager*`; tries `com/tns/AssetExtractor.extractAssets(String,String,String,Z)V`; if class missing, clears exception and still returns success. |
| `byte_89743` | 0 | none | `sub_56134(env)` | Disabled in this dump. |
| `byte_8973E` | 0 | none | `sub_3E188(env)` | Disabled in this dump. |
| `byte_89731` | 1 | none | `sub_35BE8(env)` | Calls static method on `ProtectedApplication$R$string`: decoded signature `(Landroid/content/Context;)V`; decoded method name appears as `"a"`. |

### Overall conclusion

`sub_4EB9C` is best renamed to:

```text
final_env_gate_and_java_payload_bootstrap
```

`sub_4EFB0` is best renamed to:

```text
load_hidden_java_payload_mix_v54_and_init_features
```

If the app terminates after `sub_5E684`/`sub_5F0D0` success, the next likely failing point is one of the return values inside `sub_4EB9C`/`sub_4EFB0`, especially one of the enabled feature modules above. Next useful hook: log callsite return values at `sub_4EB9C` and `sub_4EFB0` after each `BL`, plus hook `sub_4E7D8` for final MessageGuardException code.

## 2026-05-13 — `sub_4EB9C` / `sub_4EFB0` reachability and `0x2e` failure

After disabling fragile post-`sub_5F0D0` PC/callsite hooks:

```text
[sub_5E684 leave] ret=0x0 (0)
[HIT sub_4EB9C] env=... v54=... assetManager=... caller=hidden+0x4e7c8
[HIT sub_4EFB0] env=... v54=... assetManager=... caller=hidden+0x4ef98
```

Conclusion:

- `ic.dat` decrypt/decompress/check path is good.
- `sub_5E684()` succeeds and returns `0`.
- `sub_5F0D0()` is not the failing check.
- Earlier crashes around `sub_5F0D0` were caused by our overly tight instruction/callsite hooks inside/after `sub_5F0D0`.
- Execution reaches `sub_4EB9C()` and then `sub_4EFB0()`.

Observed failure:

```text
[LEAVE sub_4EFB0] ret=0x2e signed=46 FAIL
[LEAVE sub_4EB9C] ret=0x2e signed=46 FAIL
```

Initial hypothesis was that `0x2e` came from a pending Java exception immediately after `NewIntArray(8)`, because `sub_4EFB0` has early return blocks:

```asm
0x4efd8  JNIEnv->NewIntArray(8)
0x4efec  JNIEnv->ExceptionCheck()
0x4eff8  mov w0, #0x2e   ; if exception pending

0x4f018  sub_4F44C(env, intArray)
0x4f02c  JNIEnv->ExceptionCheck()
0x4f038  mov w0, #0x2e   ; if exception pending

0x4f064  JNIEnv->GetIntArrayElements(...)
0x4f078  JNIEnv->ExceptionCheck()
0x4f084  mov w0, #0x2e   ; if exception pending
```

Runtime probe showed this hypothesis is false for the first three checks:

```text
[JNI NewIntArray enter] len=8 caller=hidden+0x4efdc
[JNI NewIntArray leave] ret=0x76dba740ad
[JNI ExceptionCheck leave] ret=0x0 signed=0 caller=hidden+0x4eff0
[JNI ExceptionCheck leave] ret=0x0 signed=0 caller=hidden+0x4f030
[JNI ExceptionCheck leave] ret=0x0 signed=0 caller=hidden+0x4f07c
```

So `sub_4EFB0` continues beyond the initial Java array setup, then some later module returns `46`.

Current script state:

- `TRACE_AFTER_SUB5F0D0 = false`
- `TRACE_SUB5F0D0_INTERNALS = false`
- only function-level hooks around `sub_4EB9C`, `sub_4EFB0`, JNI `NewIntArray`, JNI `ExceptionCheck`, and `sub_4EFB0` child functions.
- no fragile mid-basic-block hooks after `sub_5F0D0`.

Next step:

Run the updated script and inspect child function logs:

```text
[child enter #x] <name> ...
[child leave #x] <name> ret=... signed=...
```

Whichever child first returns `0x2e / 46` is the failing module inside `sub_4EFB0`.


## 2026-05-13 — `assets/classes.dex.dat` decrypted container and DEX dumps

Runtime dump was added to `hook_dump_ic_dat_frida17.js`.

Backup before this change:

```text
hook_dump_ic_dat_frida17.js.bak_dump_classes_container_20260513_180114
```

### Dump flow

`assets/classes.dex.dat` is not dumped as one normal DEX directly. Runtime flow:

```text
assets/classes.dex.dat
        ↓ sub_54944(5): open protected asset id 5
        ↓ sub_3EB6C(): classes/chunk loader
        ↓ sub_3EA28(): decrypt/unpack asset into one container buffer
classes_dex_dat_decrypted_container.bin
        ↓ script parses offset table near the end of the container
classes_dex_dat_00_classes0_from_container.dex
classes_dex_dat_01_classes1_from_container.dex
classes_dex_dat_02_classes2_from_container.dex
```

### Important interpretation

`classes_dex_dat_decrypted_container.bin` is the raw decrypted/unpacked container from `assets/classes.dex.dat`. It is a binary container, not just one clean standalone DEX.

The three `.dex` files are cut directly from that container using the offsets stored in the container metadata. The script does **not** repair or mutate the DEX contents:

- no checksum fix
- no SHA1/signature fix
- no class-name patch
- no bytecode patch
- no rebuild

Each `.dex` chunk is written as:

```js
dumpMemoryToFile(name, dexPtr, fileSize);
```

where `fileSize` is read from the DEX header at offset `0x20`.

So the `.dex` files are byte-for-byte dumps from runtime memory after DexProtector decrypt/unpack, not modified artifacts generated by the script.

### Dumped files observed

```text
classes_dex_dat_00_classes0_from_container.dex  size=13186992  magic=dex\n037\0
classes_dex_dat_01_classes1_from_container.dex  size=12999919  magic=dex\n037\0
classes_dex_dat_02_classes2_from_container.dex  size=11255808  magic=dex\n037\0
classes_dex_dat_decrypted_container.bin         size=13238708
```

All three `.dex` files are valid enough for JADX GUI to load/decompile. Use:

```bash
jadx-gui dumps/ic_dat_dumps/classes_dex_dat_00_classes0_from_container.dex
jadx-gui dumps/ic_dat_dumps/classes_dex_dat_01_classes1_from_container.dex
jadx-gui dumps/ic_dat_dumps/classes_dex_dat_02_classes2_from_container.dex
```

For CLI, use checksum verification disabled because runtime dumped DEX headers have checksum/SHA1 mismatches:

```bash
jadx -Pdex-input.verify-checksum=no -d dumps/jadx_classes0 dumps/ic_dat_dumps/classes_dex_dat_00_classes0_from_container.dex
```

### Relation to current `sub_65B50` failure

The class that `sub_65B50` fails to find exists in `classes0`:

```text
Lcom/dexprotector/detector/envchecks/ProtectedApplication$ProtectedApplication$QrGen$Segment;
```

But the runtime log currently showed `sub_3EB6C` loading only:

```text
DF3FC58E29EAE0954C17E32FAEA140B4673FA808B877CB0E6F421373563DFC96/classes2
```

Therefore `FindClass("com/dexprotector/detector/envchecks/ProtectedApplication$ProtectedApplication$QrGen$Segment")` returning `0x0` is likely because `classes0` was not loaded/defined in this execution path yet, not because the class is absent from the decrypted data.

## Latest: `sub_65B50` QrGen `$Segment` field failure

Observed flow after forcing `classes0/classes1` to load:

- `FindClass("com/dexprotector/detector/envchecks/ProtectedApplication$ProtectedApplication$QrGen$Segment")` succeeds.
- `RegisterNatives` succeeds for:
  - `xDwEEmqjHh(): Segment` -> hidden `0x65EA0`
  - `Erq(String): String` -> hidden `0x65F34`
- Real `GetMethodID(<init>, "(Ljava/lang/String;Ljava/lang/String;I)V")` returns NULL, even though JADX shows the private ctor exists. Workaround: resolve the ctor by reflection and return `FromReflectedMethod` before ART/JNI initializes the class.
- Next failure is `GetStaticFieldID("wq", "Ljava/lang/String;")`. The field exists in dumped `classes0`:

```java
public static final String wq = null;
```

but calling real `GetStaticFieldID` triggers class initialization. `$Segment.<clinit>` immediately calls many `LibApplication.i(...)` opcodes:

```java
static {
    LibApplication.i(-25941, LibApplication.i(77799));
    Object objI = LibApplication.i(6961);
    LibApplication.i(10548, objI, 2);
    LibApplication.i(77798, objI);
}
```

Because the `LibApplication.i` dispatcher is not usable under our current Frida path, `<clinit>` fails. ART then marks the class erroneous, so JNI reports a misleading pending exception like `NoClassDefFoundError: ...QrGen$Segment` even though the class and field are present.

Workaround implemented in the newer scripts: replace JNI `GetStaticFieldID` for `wq:Ljava/lang/String;` and resolve it through reflection + `FromReflectedField` without calling real JNI first. This avoids triggering `$Segment.<clinit>` too early.

## Latest: real Activity path, `ProtectedApplication.s`, `sub_35BE8`, and UI shim

### `ProtectedApplication.s(String)` anti-Frida registration

`sub_55718` registers native `ProtectedApplication.s(String):String`.

Under Frida the local integrity result can mismatch. In that case DexProtector deliberately registers a bad `libart.so` JNI table pointer as the native implementation. When `MainActivity.<clinit>` calls:

```java
ProtectedApplication.s("ම")
```

ART jumps into the wrong function and crashes.

Fix in newer scripts:

```js
// in JNI RegisterNatives, if name="s" and sig="(Ljava/lang/String;)Ljava/lang/String;"
JNINativeMethod.fn = hidden_base + 0x56078;
```

`hidden+0x56078` is the real string decoder. With this patch, `s("ම")` decodes to `"envchecks"` during `MainActivity.<clinit>`.

### `sub_35BE8` callback experiment

Re-tested with `BYPASS_SUB35BE8_CALLBACK=false` after fixing QrGen ctor/field and `ProtectedApplication.s`.

Observed:

- `sub_35BE8` finds `ProtectedApplication$R$string`.
- It calls static Java method `a(Context)`:

```text
FindClass ProtectedApplication$R$string OK
GetStaticMethodID a(Context):V OK
CallStaticVoidMethod OK
```

But that Java callback spawns/executes the QrGen guard path. The guard then hits native `LibApplication.i(...)`, which is still not registered/usable under the current Frida path:

```text
NoSuchMethodError
  at com.dexprotector.detector.envchecks.LibApplication.i(Native Method)
  at ProtectedApplication$ProtectedApplication$QrGen$Segment.<clinit>
  at ProtectedApplication$R$layout.a(Native Method)
  at ProtectedApplication$R$color.<init>
  at ProtectedApplication$QrGen$Segment.run
```

Then real `MainActivity.<clinit>` also fails on the same missing `LibApplication.i` dispatcher.

Conclusion: `sub_35BE8` is safe to call only after the `LibApplication.i` dispatcher is truly fixed. For now, keep it skipped for survival.

### Real `MainActivity` survival state

Created newer scripts:

- `hook_real_activity_runthread_native_s_frida17.js`
  - real Activity, real native `ProtectedApplication.s` forced to `hidden+0x56078`
  - invokes private `MainActivity.runThread()` to trace opcodes
  - observed runThread opcodes: `9871`, `5031`, `21443`, `25941`, `73493`, `24610`, `-29853`, `14217`, `-22503`
  - default returns allow process survival but UI remains blank because thread/runnable objects are not really constructed.

- `hook_real_activity_ui_shim_frida17.js`
  - real Activity, provider stub only
  - keeps native `ProtectedApplication.s` patched to `hidden+0x56078`
  - hooks in-memory `LibApplication.i` only for the visible `MainActivity` lifecycle opcodes:
    - `4769`: class init marker, ignore
    - `-5811`: mark `Activity.mCalled=true` instead of recursively calling `Activity.onCreate`
    - `24578`: return `R.layout.activity_main = 0x7f080000`
    - `15373`: call `Activity.setContentView(layoutId)`
    - `12337`: UI shim; fills `TextView` and `ImageView`
  - reads real `android_id`
  - generates session UUID
  - populates text lines like the normal app:

```text
<time>
androidId: <real android_id>
sessionId: <uuid>
xposed: false
customFirmware: false
debugger: false
emulator: false
manualInstall: false
root: false
```

  - generates a QR-looking bitmap and sets it on `ImageView` id `0x7f060032`.

Verification artifact:

```text
/tmp/frida_ui_shim_230135.log
/tmp/dp_ui_shim.png
```

The app process stayed alive after Frida detached:

```bash
adb shell pidof com.dexprotector.detector.envchecks
# 23685
```

Important limitation: the UI shim is not the original QR algorithm. It is a survival/visual-normality workaround while `LibApplication.i` dispatcher remains unreversed.

### Current unresolved root cause

The remaining real-logic blocker is `LibApplication.i(...)`.

All 1176 overloads in dumped `LibApplication.java` are declared native. Under the current Frida path, calling the original native method throws blank `NoSuchMethodError`. This means ART has no usable native implementation for the overload, or DexProtector intentionally leaves the method unresolved until some hidden dispatcher/guard path succeeds.

Skipping `sub_35BE8` avoids the guard crash but also avoids whatever extra Java path it would run. Running `sub_35BE8` confirms the same missing `LibApplication.i` dispatcher is the blocker.

### Global `RegisterNatives` trace

Added `hook_trace_global_regnatives_frida17.js` to hook JNI `RegisterNatives` globally from `Java.vm.getEnv()` before `libdexprotector.so` loads.

Findings:

- No `RegisterNatives` call was observed for `com.dexprotector.detector.envchecks.LibApplication`.
- Early `libalice.so` registrations were only for:
  - `ProtectedApplication$MainActivity$$ExternalSyntheticLambda1` with 13 native `a/b/c` helper methods.
  - `ProtectedApplication$R$layout` with 5 native `a(...)` helper methods.
- Hidden DexProtector registrations later:
  - `ProtectedApplication$ProtectedApplication.AgqpckdwFG()[B` -> hidden `0x4F87C`
  - `ProtectedApplication.s(String):String` -> initially bad `libart.so+0x61a24c`, patched to hidden `0x56078`
  - `QrGen$Segment.xDwEEmqjHh()` -> hidden `0x65EA0`
  - `QrGen$Segment.Erq(String)` -> hidden `0x65F34`
  - `ProtectedApplication.ylGi(Object,String):InputStream` -> hidden `0x5228C`
  - `ProtectedApplication.ye()` -> hidden `0x4F9DC`

This strengthens the hypothesis that `LibApplication.i` is not registered normally through JNI `RegisterNatives`. It is likely handled by a DexProtector-specific ART/native-method dispatch mechanism or intentionally unresolved until another hidden setup succeeds.

### `sub_35BE8` detach experiment

Tried `DETACH_ALL_BEFORE_SUB35BE8_CALLBACK=true` to remove Frida Interceptor trampolines before executing original `sub_35BE8`.

Important bug found: old wrapper treated `sub_35BE8` as one-argument function. Runtime trace shows it is called with at least 4 registers (`x0..x3`). Calling the original with only `env` corrupts arguments and crashes.

Patched experimental wrappers to use:

```js
new NativeFunction(addr, 'int64', ['pointer','pointer','pointer','pointer'])
```

But using `replaceFast` + `detachAll` is still tricky: the original trampoline can be invalidated, and naïvely calling `addr` can recurse into the wrapper. Current reliable path remains: keep `sub_35BE8` skipped unless/until `LibApplication.i` is solved.

## 2026-05-13 late: LibApplication.i semantic runThread bypass experiment

New script: `hook_real_activity_semantic_runthread_frida17.js`.

Purpose: move past the `MainActivity.<clinit>` / `LibApplication.i(...)` blocker without using the earlier one-shot UI shim only. Instead of solving the protector's real native dispatcher, hook the in-memory Java overloads of `LibApplication.i` and implement the opcodes used by `MainActivity` and its two synthetic runnables.

### dlsym / native lookup trace

Created `hook_trace_dlsym_libapp_frida17.js` from `hook_real_activity_force_s_frida17.js` and hooked `dlsym`, `__loader_dlsym`, `dlopen`, and `android_dlopen_ext`.

Result:

- Saw `android_dlopen_ext` load `libalice.so` and `libdexprotector.so`.
- Saw no useful `dlsym` lookup for `LibApplication.i` / `Java_com_dexprotector...LibApplication...` before the crash.
- This supports the previous finding from global `RegisterNatives`: `LibApplication.i` is probably not registered through normal JNI `RegisterNatives` or normal libdl `dlsym`; it is likely a DexProtector ART/native-method dispatch trick or an intentionally unresolved native trap.

### QrGen$Segment pre-init status

Confirmed the newer pre-init spoof works:

```text
[JNI GetMethodID PREINIT spoof] ctor=private ...QrGen$Segment(java.lang.String,java.lang.String,int) ...
[JNI GetStaticFieldID PREINIT spoof] field=public static final java.lang.String ...QrGen$Segment.wq ...
[child leave] sub_65B50 QrGen$Segment setup ret=0 OK
```

So the old `GetStaticFieldID("wq")` / misleading `NoClassDefFoundError` issue is bypassed.

### MainActivity opcode mapping implemented

From JADX/MCP decompile:

```java
private void runThread() {
    Object finished = LibApplication.i(9871);
    LibApplication.i(5031, finished, false);
    LibApplication.i(21443, this, finished);
    Object thread = LibApplication.i(25941);
    Object runnable = LibApplication.i(73493);
    LibApplication.i(24610, runnable, this);
    LibApplication.i(-29853, thread, runnable);
    LibApplication.i(14217, this, thread);
    LibApplication.i(-22503, thread);
}
```

Important opcode meanings inferred/implemented:

- `4769`: MainActivity class init marker, ignore.
- `-5811`: `Activity.onCreate` super marker; set `Activity.mCalled=true`.
- `24578`: return `R.layout.activity_main` = `0x7f080000`.
- `15373`: call `Activity.setContentView(layoutId)`.
- `12337`: invoke private `MainActivity.runThread()` reflectively.
- `9871`: create `AtomicBoolean` for `finished`.
- `5031`: `AtomicBoolean.set(boolean)`.
- `21443`: set `MainActivity.finished`.
- `25941`: thread placeholder.
- `73493`: runnable placeholder.
- `24610` + ctor opcode `15450`: create/setup `MainActivity$$ExternalSyntheticLambda0(f$0=this)`.
- `-29853`: create `Thread(lambda0)`.
- `14217`: set `MainActivity.updatethread`.
- `-22503`: start thread.
- `-12512`: get `Lambda0.f$0`.
- `-593`: call real hidden/decompiled run-loop method (`lambda$runThread$1...` / `m49xfbbf001d`).
- `10458`: `Activity.findViewById(id)`.
- `-16137`: `TextView` id `0x7f06004f`.
- `-23676`: `ImageView` id `0x7f060032`.
- `118`: `new StringBuilder()`.
- `220`, `48`, `1097`, `-7395`: StringBuilder append operations.
- `9377`: `System.currentTimeMillis()`.
- `24312`: Android ID via `Settings.Secure.getString(..., "android_id")`.
- `15707`: UUID/session id.
- `11819`, `-26337`, `23686`, `29588`, `72447`, `-18961`: boolean detector results currently forced false (`xposed`, `customFirmware`, `debugger`, `emulator`, `manualInstall`, `root`).
- `426`: format one line as `label: value\n`.
- `285`: boolean boxing.
- `9605`/`27309`/`9363`: Handler/main-looper setup.
- `-30723`/`2663`: schedule UI update (TextView + QR-looking ImageView) on main thread.
- `-6768`: sleep.
- `6715`/`10763`/`2844`: `finished` getter/get/set.

### Stability fix

Initial semantic implementation let the real loop run every 2 seconds. That eventually crashed ART GC around ~47s:

```text
Abort message: 'klass pointer for obj ... found to be null ...'
Process crashed: Trace/BPT trap
```

Likely cause: repeated Frida-created Java wrappers/objects crossing hooks and GC compaction. Fix: after the first successful UI update, set `finished=true` so the app's update thread exits. This keeps the screen populated and avoids the GC crash in the tested window.

### Evidence

Stable run command used:

```bash
timeout 75s ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks -l hook_real_activity_semantic_runthread_frida17.js
```

Evidence log:

```text
/tmp/frida_semantic_runthread_233409.log
[semantic UI] TextView/ImageView updated by real runThread path
(no Process crashed / FATAL / Trace/BPT in the 75s run)
```

Screenshot after Frida timeout/detach while process still alive:

```text
/tmp/dp_semantic_runthread_stable.png
pidof com.dexprotector.detector.envchecks -> 25020
```

The displayed screen now has the expected TextView lines and a QR-looking ImageView. Unlike the earlier pure UI shim, this path invokes the real `MainActivity.runThread()` and real run-loop method, but `LibApplication.i` is still semantically emulated and the QR bitmap is still generated by our Frida-side QR-like renderer, not the original protector/app QR implementation.

### Current status / caveat

This is a stronger survival bypass than the earlier `hook_real_activity_ui_shim_frida17.js` because it follows the real Activity/runThread path, but it is **not** a full original-logic recovery yet:

- The real `LibApplication.i` dispatcher remains unresolved.
- QR generation is emulated with a QR-looking bitmap, not proven to match original `QrGen` output.
- The update loop is stopped after one update to avoid ART GC instability under Frida.

Therefore do not mark the overall goal complete yet if strict "fully normal original behavior" is required. Next high-value work remains reversing or locating the true `LibApplication.i` native/ART dispatch mechanism.

## 2026-05-13 late: ART-level native registration trace

New script: `hook_trace_art_regnative_frida17.js`.

Purpose: check whether `LibApplication.i` is being registered or resolved below normal JNI `RegisterNatives` / `dlsym`.

Implementation notes:

- Hooked ART `RuntimeCallbacks::RegisterNativeMethod` using Android 16 Pixel 6a libart offsets:
  - `libart.so + 0x41e7d0` = `art::RuntimeCallbacks::RegisterNativeMethod(...)`
  - attempted `libart.so + 0x288fc8` = `art::ArtMethod::PrettyMethod(ArtMethod*, bool)` for names, but direct C++ `std::string`/ArtMethod pretty-print was unreliable and returned access faults in Frida.
- Corrected hidden `this` arg: member function signature means Frida args are effectively:
  - `x0`: `RuntimeCallbacks* this`
  - `x1`: `ArtMethod* method`
  - `x2`: native function pointer
  - `x3`: out/new native pointer

Observed registrations:

- `libalice.so` normal native methods at offsets already known from global `RegisterNatives`:
  - `libalice.so+0x24994`, `+0x29c18`, `+0x293fc`, `+0x29a60`, `+0x29f1c`, `+0x29f60`, `+0x28574`, `+0x282e0`, `+0x27d20`, `+0x28a40`, `+0x29194`, `+0x27298`, `+0x2a150`
  - `libalice.so+0x4670c`, `+0x469b8`, `+0x46c30`, `+0x46c60`, `+0x46ee4`
- Hidden `libdexprotector` native registrations:
  - `ProtectedApplication$ProtectedApplication.AgqpckdwFG()[B` -> `hidden+0x4f87c`
  - `ProtectedApplication.s(String)` -> forced/patched to `hidden+0x56078`
  - `QrGen$Segment.xDwEEmqjHh()` -> `hidden+0x65ea0`
  - `QrGen$Segment.Erq(String)` -> `hidden+0x65f34`
  - `ProtectedApplication.ylGi(Object,String):InputStream` -> `hidden+0x5228c`
  - `ProtectedApplication.ye()` -> `hidden+0x4f9dc`

Important negative result:

- No ART `RegisterNativeMethod` event for `com.dexprotector.detector.envchecks.LibApplication.i(...)` before `MainActivity.<clinit>` crashes with `NoSuchMethodError`.
- No useful `JniLongName` / `JniShortName` logs for `LibApplication` were observed in this run.
- Together with earlier global JNI `RegisterNatives` and `dlsym` traces, this strongly suggests `LibApplication.i` is not being normally registered/resolved in the current path. The unresolved native method itself may be the intended trap, while the protector expects another ART-level patch/bridge that we have not found yet.

Current conclusion:

- Our semantic Java hook for `LibApplication.i` remains the practical bypass path for now.
- To fully recover original behavior, next target is not normal JNI registration; instead inspect ART method-entry patching, hidden writes to `ArtMethod` / JNIEnv table / class linker state, or reverse libalice/hidden code responsible for the `LibApplication` dispatcher.

## 2026-05-13 late: QrGen$Segment JNI setup resolved

Latest focused run:

```bash
LOG=/tmp/frida_qrseg_current_234513.log
./frida17/bin/frida -U -f com.dexprotector.detector.envchecks -l hook_dump_ic_dat_frida17.js
```

Important result: the earlier `sub_65B50` failure at `QrGen$Segment` is now understood and bypassed.

Observed native setup flow:

```text
sub_65B50 QrGen$Segment setup
  FindClass("...ProtectedApplication$ProtectedApplication$QrGen$Segment") -> class OK
  RegisterNatives count=2:
    xDwEEmqjHh()L...QrGen$Segment; -> hidden+0x65ea0
    Erq(Ljava/lang/String;)Ljava/lang/String; -> hidden+0x65f34
  GetMethodID(<init>, "(Ljava/lang/String;Ljava/lang/String;I)V")
  GetStaticFieldID("wq", "Ljava/lang/String;")
```

Why it failed before:

- `QrGen$Segment.<clinit>` calls `LibApplication.i(...)`:

```java
static {
    LibApplication.i(-25941, LibApplication.i(77799));
    Object objI = LibApplication.i(6961);
    LibApplication.i(10548, objI, 2);
    LibApplication.i(77798, objI);
}
```

- JNI `GetStaticFieldID()` may trigger class initialization. Because the real `LibApplication.i` dispatcher is not resolved under Frida, this poisoned the class and later showed as `NoClassDefFoundError`.
- `GetMethodID(<init>)` also returned NULL in this path despite reflection showing the private constructor exists.

Bypass used:

- Replace `JNIEnv->GetMethodID` only for `QrGen$Segment.<init>(String,String,int)`:
  - resolve constructor via Java reflection
  - convert reflected constructor to `jmethodID` with `FromReflectedMethod`
  - return that method ID and clear pending exception
- Replace `JNIEnv->GetStaticFieldID` only for `QrGen$Segment.wq:Ljava/lang/String;`:
  - resolve field via Java reflection
  - convert to `jfieldID` with `FromReflectedField`
  - return that field ID without calling real `GetStaticFieldID`, avoiding `<clinit>`

Evidence:

```text
[JNI GetMethodID PREINIT spoof] ctor=private ...QrGen$Segment(java.lang.String,java.lang.String,int) handle=0x372a mid=0x7340029830
[JNI GetStaticFieldID PREINIT spoof] field=public static final java.lang.String ...QrGen$Segment.wq handle=0x374e fid=0x73400297ec
[child leave #10] sub_65B50 QrGen$Segment setup ret=0x0 signed=0 OK
```

The field is real. JADX names it `f56wq`, but runtime/reflection string is `...QrGen$Segment.wq`.

After this fix, `sub_4EFB0` and `sub_4EB9C` can return OK in the focused dump script:

```text
[LEAVE sub_4EFB0 #5] ret=0x0 signed=0 OK
[LEAVE sub_4EB9C #4] ret=0x0 signed=0 OK
```

Remaining non-original part in that script:

- `ProtectedAppComponentFactory.instantiateActivity` is still stubbed to `FridaStubActivity` in `hook_dump_ic_dat_frida17.js`, so it proves native initialization but not normal UI behavior.
- Normal UI survival is currently handled by `hook_real_activity_semantic_runthread_frida17.js`, which uses a semantic `LibApplication.i` hook.

## 2026-05-13 late: libalice.so JNI_OnLoad static decode notes

`libalice.so` exports only `JNI_OnLoad`. It decodes obfuscated class/method/signature strings with helper `sub_46358` before calling `RegisterNatives`.

Helper behavior:

- input blob begins with 8 seed bytes
- every 8 output bytes, it derives an 8-byte XOR keystream from the two 32-bit seed words and a static table at `libalice.so+0xe808`
- output byte = encoded byte XOR keystream byte

Decoded signatures from `JNI_OnLoad` include the method table already observed dynamically for `ProtectedApplication$MainActivity$$ExternalSyntheticLambda1`, e.g.:

```text
(Ljava/lang/String;)V
(Landroid/content/Context;)V
([BJ)Ljava/net/HttpURLConnection;
(Ljava/lang/String;)Ljava/net/HttpURLConnection;
()Z
()Ljava/lang/String;
(Ljava/lang/String;Ljava/lang/String;IZLjava/util/List;ILjava/lang/String;I)V
(Ljava/lang/String;Ljava/lang/String;IZLjava/util/List;Ljava/util/List;ILjava/lang/String;I)V
(Ljava/lang/Throwable;)Ljava/lang/String;
(ILjava/lang/String;)Ljava/lang/String;
(ILjava/lang/String;Z)Ljava/lang/String;
```

Negative result remains: libalice `JNI_OnLoad` registers its own helper classes (`MainActivity$$ExternalSyntheticLambda1`, `R$layout` helpers) and still does not register `LibApplication.i`.

## 2026-05-13 late verification: semantic real-Activity script still stable after QrGen notes

Re-verified `hook_real_activity_semantic_runthread_frida17.js` after adding reflection-field logging helper.

Command/evidence:

```bash
LOG=/tmp/frida_semantic_verify_235036.log
adb shell am force-stop com.dexprotector.detector.envchecks
./frida17/bin/frida -U -f com.dexprotector.detector.envchecks -l hook_real_activity_semantic_runthread_frida17.js
adb exec-out screencap -p > /tmp/dp_semantic_verify_235036.png
adb shell pidof com.dexprotector.detector.envchecks
# 25591
```

Important log lines:

```text
[JNI GetMethodID PREINIT spoof] ctor=private ...QrGen$Segment(java.lang.String,java.lang.String,int) handle=0x372a mid=0x7340029830
[JNI GetStaticFieldID PREINIT spoof] field=public static final java.lang.String ...QrGen$Segment.wq handle=0x37b2 fid=0x73400297ec
[child leave #10] sub_65B50 QrGen$Segment setup ret=0x0 signed=0 OK
[LEAVE sub_4EB9C #4] ret=0x0 signed=0 OK
[Java bypass] ProtectedAppComponentFactory.instantiateActivity com.dexprotector.detector.envchecks.MainActivity -> stock real activity
[hooked] IN-MEMORY LibApplication.i semantic bypass overloads=1176
[semantic UI] TextView/ImageView updated by real runThread path
Thank you for using Frida!
```

No `Process crashed`, `FATAL`, or `Trace/BPT` occurred in the timed run. Process remained alive after Frida detached. Screenshot saved at `/tmp/dp_semantic_verify_235036.png`.

Status: anti-Frida/native-init survival is strong. Still not final full-original behavior because `LibApplication.i` is emulated semantically and QR rendering is Frida-side, not proven original app QR output.

## 2026-05-14: ArtMethod / JniId probe for `LibApplication.i`

Added a read-only ArtMethod probe inside `hook_real_activity_semantic_runthread_frida17.js` behind:

```js
const DUMP_LIBAPP_ARTMETHODS = false;
```

Enable only when tracing. It uses:

- `JNIEnv->FromReflectedMethod` to get `jmethodID`
- Android 16 libart `art::jni::JniIdManager::DecodeMethodId` at `libart.so+0x81f798`
  - important: this wrapper branches to `DecodeGenericId(this, id)`, so call it as two args: `DecodeMethodId(NULL, jmethodID)` for pointer-style low-bit-0 IDs.

Evidence run:

```text
/tmp/frida_semantic_artmethod3_000054.log
```

Observed for first `LibApplication.i` overloads before installing the semantic Java override:

```text
[artmethod] LibApplication declared_methods=1176; dumping first native i overloads before semantic override
LibApplication.i[0] ... flags=0x10200109 data@+24=boot.oat+0x314030
LibApplication.i[1] ... flags=0x10200109 data@+24=boot.oat+0x314030
...
```

Interpretation:

- `flags=0x10200109` includes public/static/native-like flags.
- The methods still point at the generic ART/native trampoline area (`boot.oat+0x314030`), not at hidden/libalice code.
- No ART `RuntimeCallbacks::RegisterNativeMethod` event was ever observed for `LibApplication.i`.

Comparison methods that are registered by hidden DexProtector do show up in ART registration trace with native pointers, e.g.:

```text
ProtectedApplication.s(String) -> hidden+0x56078
QrGen$Segment.xDwEEmqjHh() -> hidden+0x65ea0
QrGen$Segment.Erq(String) -> hidden+0x65f34
ProtectedApplication.ylGi(Object,String) -> hidden+0x5228c
ProtectedApplication.ye() -> hidden+0x4f9dc
```

Conclusion strengthened:

- `LibApplication.i` is not registered via normal JNI/ART native registration in this Frida path.
- The current real blocker is not a missed `RegisterNatives` call; it is likely a DexProtector-specific method dispatch/patch mechanism that either never runs under Frida or intentionally leaves these methods unresolved as traps.
- Current practical bypass remains semantic Java-level emulation of `LibApplication.i`.

## 2026-05-14: remove provider stub and generate standards-valid QR

Improved `hook_real_activity_semantic_runthread_frida17.js`:

### Real provider path

Changed:

```js
const STUB_PROVIDERS_FOR_SURVIVAL = false;
```

`ProtectedAppComponentFactory.instantiateProvider(...)` now installs the same `ProtectedApplication.s` + semantic `LibApplication.i` hooks before delegating to stock `AppComponentFactory`:

```js
installProtectedApplicationSBypass();
installInMemoryLibApplicationBypass();
return stockInstantiateProvider.call(stock, cl, name);
```

Evidence:

```text
/tmp/frida_semantic_provider_real_main_001422.log
[Java bypass] ProtectedAppComponentFactory.instantiateProvider com.google.firebase.provider.FirebaseInitProvider -> stock real provider
[hooked] IN-MEMORY LibApplication.i semantic bypass overloads=1176
```

So the stable script no longer uses `FridaStubProvider` for the Firebase provider.

### QR generation

Replaced the earlier QR-looking pseudo-pattern with a self-contained standards-valid QR generator in Frida JS:

- QR byte mode
- ECC level L
- supports versions 1..40
- Reed-Solomon ECC and interleaving
- fixed mask 0 with proper format/version/function modules
- renders a `1000 x 1000` Android `Bitmap`

Reason: the app's Java `QrGen` implementation is also routed through `LibApplication.i`, so calling it directly would require fully recovering the dispatcher. A local QR implementation gets the visible UI much closer to normal behavior without relying on unresolved protector dispatch.

Evidence:

```text
[semantic QR] generated valid byte-mode QR ver=9 bytes=229
[semantic UI] TextView/ImageView updated by real runThread path
```

Latest verification artifacts:

```text
/tmp/frida_semantic_provider_real_main_001422.log
/tmp/dp_semantic_provider_real_main_001422.png
pidof com.dexprotector.detector.envchecks -> 27876
```

No `Process crashed`, `FATAL`, or `Trace/BPT` in the timed run. Frida detached and the app process stayed alive.

### Current best script status

`hook_real_activity_semantic_runthread_frida17.js` now:

- loads native DexProtector successfully
- decrypts/dumps protected assets as before
- runs real Firebase provider path through stock factory
- runs real `MainActivity` path through stock factory
- uses real `ProtectedApplication.s` native decoder (`hidden+0x56078`)
- uses semantic `LibApplication.i` emulation for the protected Java dispatcher
- displays real activity UI text
- displays a valid QR bitmap instead of a fake QR-like pattern

Remaining strict caveat: the true original `LibApplication.i` native/ART dispatcher is still not recovered; it remains emulated at Java level.

## 2026-05-14: real `sub_35BE8` callback enabled

Previously `sub_35BE8` was skipped because it calls `ProtectedApplication$R$string.a(Context)`, which triggers `LibApplication.i(...)` while the dispatcher is unresolved under Frida.

New fix in `hook_real_activity_semantic_runthread_frida17.js`:

```js
const BYPASS_SUB35BE8_CALLBACK = false;
const INSTALL_LIBAPP_BEFORE_SUB35BE8_CALLBACK = true;
```

Implementation:

- expose the semantic `LibApplication.i` installer from the Java hook closure:

```js
globalThis.__dpInstallInMemoryLibApplicationBypass = installInMemoryLibApplicationBypass;
```

- wrap `hidden+0x35BE8` with `replaceFast`
- before calling original `sub_35BE8`, run the semantic installer with `Java.performNow(...)`
- then call original `sub_35BE8`

Evidence:

```text
/tmp/frida_sub35_real_main_002233.log
[replaceFast] sub_35BE8 install-LibApplication-before-original wrapper @ ... orig=...
[sub_35BE8 wrapper] env=...; install semantic LibApplication.i before real R$string callback
[hooked] IN-MEMORY LibApplication.i semantic bypass overloads=1176
[sub_35BE8 wrapper] original returned 0
[Java bypass] ProtectedAppComponentFactory.instantiateProvider ...FirebaseInitProvider -> stock real provider
[Java bypass] ProtectedAppComponentFactory.instantiateActivity ...MainActivity -> stock real activity
[semantic QR] generated valid byte-mode QR ver=9 bytes=229
[semantic UI] TextView/ImageView updated by real runThread path
Thank you for using Frida!
pidof -> 28158
```

Screenshot:

```text
/tmp/dp_sub35_real_main_002233.png
```

Result: one more native/Java guard path is now executed instead of skipped. The current best script runs real `sub_35BE8`, real provider, and real Activity path. Remaining non-original piece is still semantic `LibApplication.i` emulation and one-shot UI update.

### Tried / ruled out: Frida-side periodic UI updater

Experimented with a Frida-side `setInterval(..., 2000)` updater to mimic the app's repeated UI refresh while keeping the original protected loop stopped.

Evidence:

```text
/tmp/frida_periodic_ui_002510.log
[semantic UI periodic] started 2s Frida-side updater
[semantic UI periodic] update #1
...
[semantic UI periodic] update #10
Process crashed: Trace/BPT trap
```

Conclusion: periodic Frida-driven Java/Bitmap updates still eventually trip ART/Frida GC/runtime instability. The stable script keeps:

```js
const ENABLE_PERIODIC_UI_UPDATER = false;
```

and performs a one-shot UI update. This is less dynamic than the original app loop, but it is stable after Frida detach and avoids the previous `Trace/BPT` crash.

Re-verified after disabling periodic updater:

```text
/tmp/frida_stable_after_periodic_disable_002605.log
/tmp/dp_stable_after_periodic_disable_002605.png
[sub_35BE8 wrapper] original returned 0
[Java bypass] ...FirebaseInitProvider -> stock real provider
[Java bypass] ...MainActivity -> stock real activity
[semantic QR] generated valid byte-mode QR ver=9 bytes=229
[semantic UI] TextView/ImageView updated by real runThread path
Thank you for using Frida!
pidof -> 28346
```

No `Process crashed`, `FATAL`, or `Trace/BPT` in the 70s timed run.

## 2026-05-14: packaged stable bypass script

Created cleaned runnable script:

```text
bypass_envchecks_frida17.js
```

Usage:

```bash
./frida17/bin/frida -U -f com.dexprotector.detector.envchecks -l bypass_envchecks_frida17.js
```

Differences from research script:

- keeps the stable bypasses
- disables classes.dex.dat container/chunk dumping to reduce file I/O noise:

```js
const DUMP_CLASSES_DEX_CONTAINER = false;
const DUMP_CLASSES_DEX_CHUNKS = false;
```

Verification:

```text
/tmp/frida_bypass_clean_002812.log
/tmp/dp_bypass_clean_002812.png
```

Key evidence:

```text
[sub_35BE8 wrapper] original returned 0
[Java bypass] ProtectedAppComponentFactory.instantiateProvider ...FirebaseInitProvider -> stock real provider
[Java bypass] ProtectedAppComponentFactory.instantiateActivity ...MainActivity -> stock real activity
[semantic QR] generated valid byte-mode QR ver=9 bytes=229
[semantic UI] TextView/ImageView updated by real runThread path
Thank you for using Frida!
pidof -> 28431
```

No `Process crashed`, `FATAL`, or `Trace/BPT` in this run.

### Tried / pending: compiled Dex UI updater

Experimented with an external compiled Java helper:

```text
build/ui_updater/src/com/dexprotector/detector/envchecks/FridaUiUpdater.java
build/ui_updater/dex/classes.dex
```

Goal: start a pure-Java `Handler` updater from Frida once, so periodic TextView refreshes happen in ART bytecode instead of repeated Frida callbacks.

First attempt failed because only `FridaUiUpdater.class` was passed to `d8`, so the anonymous inner Runnable class was missing:

```text
[dex UI updater] unavailable (/data/local/tmp/dp_ui_updater.dex):
java.lang.NoClassDefFoundError: Failed resolution of: Lcom/dexprotector/detector/envchecks/FridaUiUpdater$1;
```

Fixed the build command to include all `.class` files:

```bash
/home/namnh/Android/Sdk/cmdline-tools/latest/bin/d8 --min-api 23 --output build/ui_updater/dex $(find build/ui_updater/classes -name '*.class')
```

But device/ADB disconnected before the fixed dex could be pushed and verified. Therefore the stable scripts keep this disabled:

```js
const USE_DEX_UI_UPDATER = false;
```

The one-shot UI path remains the verified stable mode.

### 2026-05-14: pending test — satisfy `sub_3EB6C` selector compare without return spoof

Concern: the previous `classes.dex.dat` selector bypass may be too invasive:

```c
v12 = sub_6A05C(hidden_base, 0x7caa0, 0);
v13 = *(container_end - 0x20);
if (v12 == v13)
    load /classes0 and /classes1;
else
    load fallback /classes2;
```

Old script behavior:

```text
replace sub_6A05C return value: real_v12 -> v13
```

That makes the branch pass, but it hides the real code hash and may perturb later
state if the protector expects the real hash value.

Disassembly confirms a better hook point:

```asm
hidden+0x3ec58  bl   sub_6A05C
hidden+0x3ec60  mov  x9, x0              ; real v12
hidden+0x3ec64  ldur x14, [x21, #-0x20]  ; v13 loaded AFTER return
hidden+0x3ecc4  cmp  x9, x14
```

New experimental script:

```text
bypass_envchecks_selector_realmatch_frida17.js
```

New behavior:

```text
do not replace sub_6A05C return;
onLeave(sub_6A05C), write real_v12 into *(container_end - 0x20);
the real subsequent load+cmp sees v12 == v13 naturally.
```

Expected log:

```text
[classes.dex.dat selector real-match] real_v12=... old_v13=... new_v13=...; retval unchanged; cmp should be true
```

Verification status: **not yet verified**. ADB disconnected before Frida could spawn:

```text
Waiting for USB device to appear...
adb devices -> no devices
```

Additional less-invasive variant prepared:

```text
bypass_envchecks_selector_cleancopy_frida17.js
```

Purpose: make `v12` become the clean-image selector hash without replacing
`sub_6A05C()` return and without modifying the decrypted container's expected
`v13` field.

Method:

1. At the clean point `outer JNI_OnLoad before hidden entry`, before hidden
   `Interceptor` hooks are installed, copy:

   ```text
   hidden_base .. hidden_base+0x7caa0
   ```

   into Frida heap memory.

2. At the later selector call:

   ```c
   sub_6A05C(hidden_base, 0x7caa0, 0)
   ```

   only for caller `hidden+0x3ec5c`, rewrite argument `x0` from the now-dirty
   hidden base to the clean snapshot. The function still returns its real
   computed hash:

   ```text
   v12 = sub_6A05C(clean_snapshot, 0x7caa0, 0)
   v13 = *(container_end - 0x20)   // untouched original expected value
   ```

Expected log:

```text
[runtime clean hidden snapshot] src=... dst=... len=0x7caa0
[classes.dex.dat selector clean-copy] v12=... v13=... match=true; retval unchanged; expected field untouched
```

This is closer to the original condition than the `realmatch` variant:

- no branch patch
- no return-value spoof
- no expected-field patch
- only selector hash input is redirected to the clean hidden image snapshot

Verification status: **verified** with:

```text
/tmp/frida_selector_bypass_envchecks_selector_cleancopy_frida17_084034.log
/tmp/dp_selector_cleancopy_app_084034.png
```

Key evidence:

```text
[runtime clean hidden snapshot] src=0x7408e70000 dst=0x76aac00010 len=0x7caa0
[classes.dex.dat selector clean-copy] v12=0x4169c1cc97e045b1 v13=0x4169c1cc97e045b1 match=true; retval unchanged; expected field untouched
[child leave #10] sub_65B50 QrGen$Segment setup ret=0x0 signed=0 OK
[sub_35BE8 wrapper] original returned 0
[LEAVE sub_4EFB0 #5] ret=0x0 signed=0 OK
[LEAVE sub_4EB9C #4] ret=0x0 signed=0 OK
[semantic QR] generated valid byte-mode QR ver=9 bytes=229
[semantic UI] TextView/ImageView updated by real runThread path
Thank you for using Frida!
pidof -> 13053
```

The screenshot shows the app UI with env status text and QR code. This proves
the selector condition is now satisfied through the real `sub_6A05C()` return
and the original `v13` expected value, without branch/return/expected-field
spoofing for this `v12 == v13` gate.

### 2026-05-14: test without semantic `LibApplication.i` dispatcher bypass

Created:

```text
bypass_envchecks_selector_no_dispatcher_frida17.js
```

This keeps the clean-copy selector fix above, but disables the semantic
`LibApplication.i(...)` emulation:

```text
[TEST no-dispatcher] semantic LibApplication.i bypass disabled; leaving original/native dispatcher untouched
```

Result:

```text
/tmp/frida_selector_bypass_envchecks_selector_no_dispatcher_frida17_084659.log
```

Native/protector setup still succeeds:

```text
[classes.dex.dat selector clean-copy] v12=0x4169c1cc97e045b1 v13=0x4169c1cc97e045b1 match=true; retval unchanged; expected field untouched
[child leave #10] sub_65B50 QrGen$Segment setup ret=0x0 signed=0 OK
[child leave #14] sub_35BE8 R$string callback ret=0x0 signed=0 OK
[LEAVE sub_4EFB0 #5] ret=0x0 signed=0 OK
[LEAVE sub_4EB9C #4] ret=0x0 signed=0 OK
```

But when Android instantiates real providers/Activity, the original
`LibApplication.i(Native Method)` still throws blank `NoSuchMethodError`.

First provider-side failure:

```text
java.lang.NoSuchMethodError: 
  at com.dexprotector.detector.envchecks.LibApplication.i(Native Method)
  at com.dexprotector.detector.envchecks.ProtectedApplication$ProtectedApplication$QrGen$Segment.<clinit>(Unknown Source:3)
  at com.dexprotector.detector.envchecks.ProtectedApplication$R$layout.a(Native Method)
  at com.dexprotector.detector.envchecks.ProtectedApplication$R$color.<init>(Unknown Source:70)
  at com.dexprotector.detector.envchecks.ProtectedApplication$QrGen$Segment.run(Unknown Source:51)
  at com.dexprotector.detector.envchecks.LibApplication.i(Native Method)
  at com.google.firebase.provider.FirebaseInitProvider.<clinit>(FirebaseInitProvider.java:38)
```

Then Activity launch fails:

```text
java.lang.NoSuchMethodError: 
  at com.dexprotector.detector.envchecks.LibApplication.i(Native Method)
  at com.dexprotector.detector.envchecks.MainActivity.<clinit>(MainActivity.java:26)
  at java.lang.Class.newInstance(Native Method)
  at android.app.AppComponentFactory.instantiateActivity(AppComponentFactory.java:97)
```

Process ends with:

```text
Process crashed: java.lang.NoSuchMethodError:
FATAL EXCEPTION: main
```

Conclusion: the `v12 == v13` selector gate was not the remaining reason the
dispatcher is unusable. With that gate satisfied naturally, the original
`LibApplication.i` native dispatcher still fails at class initialization time.
The semantic `LibApplication.i` bypass is still required unless we recover the
real dispatcher binding/patching path.

### 2026-05-14: locating `dp.mp3` decode/decrypt path

Static scan of all `sub_401B0` decode call sites found the `dp.mp3` asset name
inside `sub_54944`, the common asset-open helper.

Important addresses:

```text
sub_54944(a1, out3)      = open decoded asset by small id
decode function          = sub_401B0
common decode call       = hidden+0x54A20
dp.mp3 setup branch      = hidden+0x549CC
dp.mp3 encoded blob      = hidden+0x12D1
decode length            = 65
decoded string           = "dp.mp3"
```

Relevant decompiled switch:

```c
sub_54944(id, out3) {
    switch (id) {
      case 1: blob = 0x2A05; // "se.dat"
      case 2: blob = 0x4644; // "resources.dat"
      case 3: blob = 0x0BDB; // "mm.dat"
      case 4: blob = 0x12D1; // "dp.mp3"
      case 5: blob = 0x480C; // "classes.dex.dat"
      case 6: blob = 0x5F5B; // "ic.dat"
      case 7: blob = 0x2E64; // "ct.dat"
      case 8: blob = 0x4855; // "rcdb.dat"
    }
    name = sub_401B0(blob, tmp, 65);
    return open_asset(name, out3);
}
```

`dp.mp3` is opened by `sub_402E0`:

```text
sub_402E0+0x2C / hidden+0x4030C:
    sub_54944(4, out3);   // id 4 => "dp.mp3"
```

Then `sub_402E0` decrypts and decompresses it:

```c
sub_402E0(env, v54, flag) {
    if (sub_54944(4, asset) != 0)      // dp.mp3
        return 4;

    sub_15DD4(v54, 0, 0, key44, 0x2c); // derive 44-byte key/material
    sub_203DC(ctx);
    sub_20428(ctx, key44);

    // decrypt encrypted dp.mp3 asset bytes
    ret = sub_20754(ctx,
                    asset_size - 16,
                    &nonce_or_len,
                    0, 0,
                    asset_base + asset_size - 16, // tag/end
                    asset_base,                   // ciphertext
                    decrypted_tmp);

    decompressed_size = *(uint32_t *)decrypted_tmp;
    decompressed = malloc(decompressed_size);

    // decompress decrypted payload
    written = sub_71844(decompressed,
                        decompressed_size,
                        decrypted_tmp + 4,
                        asset_size - 20);

    // first qword of decompressed dp.mp3 must match clean hidden hash
    if (sub_6A05C(hidden_base, 0x7caa0, 0) == *(uint64_t *)decompressed)
        byte_8CB48 = 1;

    // then uses the decompressed tables to install/resolve protected access
    // paths via sub_4E340/sub_41108/... and later sub_4DDB4/sub_4E338.
}
```

This means our earlier label `sub_402E0 asset4/payload loader` is actually the
`dp.mp3` decrypt/decompress/init path. It is likely the best next target for
the broken original `LibApplication.i` dispatcher, because Romain Thomas'
DexProtector write-up says `dp.mp3` stores the protected method/field access
metadata used by the native bridge.

## 2026-05-14 — extra hooks: `dp.mp3` clean-hash and real `LibApplication.i` dispatcher

New scripts created:

```text
hook_dp_mp3_cleanhash_dispatcher_trace_frida17.js
hook_dp_mp3_cleanhash_dispatcher_shim9320_frida17.js
hook_dp_mp3_cleanhash_realdispatcher_keystore_bypass_frida17.js
```

Main result:

```text
[DPMP3 hash clean-copy] arg0 hidden_base -> clean_snapshot
[DPMP3 hash leave] real=0x4169c1cc97e045b1 expected=0x4169c1cc97e045b1 match=true
[DPMP3 sub_41108 table_install_B leave] ret=0
[DPMP3 leave] byte_8CB48_after=1
[LEAVE sub_4EB9C] ret=0 OK
```

Meaning: `dp.mp3` decrypt/decompress was already OK. The missing piece was the
hash gate inside `sub_402E0`: under Frida the hidden image is dirty, so
`sub_6A05C(hidden_base, 0x7caa0, 0)` did not match the first qword inside the
unpacked `dp.mp3` table. Redirecting only that hash input to the clean hidden
snapshot makes the table install path run:

```text
sub_402E0 -> sub_41108(...) -> byte_8CB48 = 1
```

After that, the original/native `LibApplication.i` dispatcher starts working.
Trace evidence:

```text
[hooked] TRACE real IN-MEMORY LibApplication.i overloads=1176
[LibApplication.i real enter] op=4769 ...
[LibApplication.i real enter] op=70991 ...
[LibApplication.i real enter] op=21390 ...
...
```

The earlier `NoSuchMethodError` for `QrGen$Segment` is gone once `dp.mp3` table
install succeeds. Old reflection spoof for `QrGen$Segment.<init>`/`wq` is now
unneeded and can corrupt ART/GC, so the new trace script disables it:

```text
ENABLE_PREINIT_QRSEGMENT_SPOOF = false
TRACE_FINAL_JNI_EXCEPTIONCHECK = false
```

Next runtime issue seen with the real dispatcher is not DexProtector table load;
it is app/environment behavior in `KeystoreUtils.getKeyAttestationExt()`:

```text
LibApplication.i op=9320 -> KeyPairGenerator.initialize(KeyGenParameterSpec)
throws: Secure lock screen must be enabled to create keys requiring user authentication
```

Naively skipping opcode `9320` is wrong: the following `generateKeyPair()` fails
with `IllegalStateException: Not initialized`.

Better bypass is to hook the Java method itself:

```text
KeystoreUtils.getKeyAttestationExt() -> fake empty String
```

`hook_dp_mp3_cleanhash_realdispatcher_keystore_bypass_frida17.js` does exactly
that while leaving the original/native `LibApplication.i` dispatcher active and
traced.

### `sub_402E0` comparison truth trace

Created:

```text
hook_sub402E0_cmp_truth_frida17.js
```

Purpose: trace the real comparisons in `sub_402E0` and make them pass by
providing correct inputs, not by forcing branch flags/return values.

Important compare sequence from IDA:

```c
written = sub_71844(decompressed, expected_size, compressed, compressed_len);
if (written != expected_size) return 9;

hash = sub_6A05C(hidden_base, 0x7caa0, 0);
if (hash == *(uint64_t *)decompressed) {
    byte_8CB48 = 1;
    ok = 1;
} else {
    ok = byte_8CB48;
}

if (ok) {
    if (sub_36618(name_len) & 1)
        ret = sub_41108(env, table2, count2, table1, count1, strings);
    else
        ret = sub_4E340(table2, count2, table1, count1, strings);
    if (ret) return ret;
}

cls = FindClass(name);
if (ExceptionCheck()) return 46;
ret = (sub_36618(0) & 1) ? sub_4DDB4(env, cls) : sub_4E338(cls);
if (ret) return ret;
```

Observed with truth trace:

```text
written=0x31e262 expected=0x31e262 equal=true
hash=0x4169c1cc97e045b1 dpmp3_first_qword=0x4169c1cc97e045b1 equal=true
w26=1 byte_8CB48=1
sub_36618_ret=0x1 bit0=1 -> sub_41108
sub_41108 ret=0
ExceptionCheck_ret=0
sub_4DDB4 ret=0
```

The hash compare is made true by redirecting `sub_6A05C` input from dirty
Frida-patched hidden image to the clean snapshot captured before hooks. No branch
condition or compare result is directly overwritten.

### Clean dispatcher test after fixing `dp.mp3` hash gate

Goal: keep the real Java/native dispatcher path (`LibApplication.i`) intact after
fixing native `sub_402E0` with clean-image hashing. Avoid Java dispatcher spoofing
and observe where runtime fails.

Scripts created/tested:

```text
hook_clean_dpmp3_no_java_frida17.js
hook_clean_dpmp3_factory_only_frida17.js
hook_clean_dpmp3_factory_gc_frida17.js
hook_clean_dpmp3_factory_stub_provider_gc_frida17.js
hook_clean_dpmp3_provider_stub_gc_frida17.js
```

Common native result in all clean tests:

```text
[DPMP3 decrypt leave] ret=0
[DPMP3 decompress leave] written=0x31e262 expected=0x31e262
[DPMP3 hash clean-copy] hidden_base -> clean_snapshot
[DPMP3 hash leave] real=0x4169c1cc97e045b1 expected=0x4169c1cc97e045b1 match=true
[DPMP3 sub_41108 table_install_B leave] ret=0
[DPMP3 sub_4DDB4 post_setup_A leave] ret=0
[DPMP3 leave] ret=0 byte_8CB48_after=1
```

So `dp.mp3` decrypt/decompress/table install is now correct. The remaining crash
is later Java/ART runtime interaction, not the native `sub_402E0` comparison.

Clean test outcomes:

1. **No Java factory hooks** (`hook_clean_dpmp3_no_java_frida17.js`): native init
   and dp.mp3 pass, then crash while Android instantiates manifest providers.
2. **Factory -> stock + GC no-op** (`hook_clean_dpmp3_factory_gc_frida17.js`):
   provider path still crashes inside ART `InvokeWithVarArgs` while
   `AppComponentFactory.instantiateProvider()` initializes provider class.
3. **Stub provider + stock activity**
   (`hook_clean_dpmp3_factory_stub_provider_gc_frida17.js`): provider no longer
   crashes, then crash moves to activity creation.
4. **Only stub provider, leave Activity/Application factory paths untouched**
   (`hook_clean_dpmp3_provider_stub_gc_frida17.js`): provider passes, then same
   activity/class-init crash appears inside `AppComponentFactory.instantiateActivity()`.

Important evidence from latest run:

```text
[provider-stub] instantiateProvider com.google.firebase.provider.FirebaseInitProvider -> StubProvider
[provider-stub] StubProvider.onCreate -> true
Process crashed: Bad access due to invalid address
backtrace: art::InvokeWithVarArgs -> JNI CallStaticObjectMethod -> <anonymous dumped dex> -> ClassLinker::InitializeClass -> AppComponentFactory.instantiateActivity
```

Interpretation: after real `sub_402E0` table install, the crash is caused by
class initialization / dispatcher calls from the dynamically loaded dex while
Frida is attached. Stubbing provider only proves the provider itself is not the
root cause; the failure follows to `MainActivity` class initialization. Do not
re-enable the old `QrGen$Segment` reflection spoof here; it is no longer needed
and can corrupt ART state. Next useful target is tracing the real dispatcher call
from class `<clinit>`/activity initialization without wrapping `LibApplication.i`
in a way that changes Java exception behavior.

Log files:

```text
/tmp/frida_clean_dpmp3_factory_gc_110913.log
/tmp/frida_clean_dpmp3_factory_stub_provider_gc_111033.log
/tmp/frida_clean_dpmp3_provider_stub_gc_111117.log
```

#### Direct confirmation: `sub_4DDB4` and `sub_54B10` after `dp.mp3`

Added one-off script:

```text
hook_clean_dpmp3_provider_stub_gc_trace54b10_frida17.js
```

Confirmed both helpers are hit from `sub_402E0` after `dp.mp3` hash/table install:

```text
[DPMP3 sub_4DDB4 post_setup_A enter] caller=hidden+0x40550
[DPMP3 sub_4DDB4 post_setup_A leave] ret=0
[DPMP3 sub_54B10 final_stacktrace_helper enter] caller=hidden+0x405bc
[DPMP3 sub_54B10 final_stacktrace_helper leave] ret=0
[DPMP3 leave] ret=0 byte_8CB48_after=1
```

So `sub_402E0` fully completes normally through both post-setup helpers. Current
crash happens later, after returning to Java/ART class initialization.

#### `v54` cleanliness and post-`dp.mp3` chain return confirmation

Created one-off tracer:

```text
hook_clean_dpmp3_chain_returns_frida17.js
```

Important: `v54` is not a static immutable buffer; it is a rolling crypto/check
context. It is expected to mutate after each `sub_15EC8(v54, out, constant, 8)`.
"Clean" here means **not poisoned by the integrity/tamper branch** and producing
expected stage keys.

Evidence that current `v54` is clean enough for the init chain:

```text
[sub_15DD4 actual]
v54=2fb0981db149168fce51e77f4a152d94b020089cd7c5f5b65bf3dc21a7b565d4
input=5994656b07fba491
out=8ff9a6be
expected=8ff9a6be
v54_ok=true
```

Then the `dp.mp3` and all subsequent native init stages return success:

```text
[DPMP3 leave] ret=0 byte_8CB48_after=1
[CHAIN leave] sub_55718 string/native_decoder_setup ret=0 OK
[CHAIN leave] sub_65B50 QrGen_Segment_setup ret=0 OK
[CHAIN leave] sub_51E4C asset_openNonAsset_setup ret=0 OK
[CHAIN leave] sub_53390 resource_hook_setup ret=0 OK
[CHAIN leave] sub_51A10 optional_AssetExtractor_setup ret=0 OK
[CHAIN leave] sub_35BE8 final_java_callback ret=0 OK
[outer JNI_OnLoad after hidden] hidden_ret=0 signed=0
```

Interpretation: for these native init functions, return `0` really is the
success path because each caller checks `if (!result) continue; else abort`.
This does not guarantee the later Java app will not crash; it only proves the
native protector init pipeline finished successfully and returned JNI success.

#### Outer `JNI_OnLoad` return-site confirmation

Created:

```text
hook_jni_onload_return_confirm_frida17.js
```

Because the entry hook restores LR for safety, Frida `onLeave` may be skipped, so
we hooked the outer epilogue directly:

```text
libdexprotector.so+0x480
```

Runtime evidence:

```text
[outer JNI_OnLoad after hidden] hidden_ret=0x0 signed=0; outer will return JNI_VERSION_1_4(0x10004)
[outer JNI_OnLoad RETSITE normal] pc=libdexprotector.so+0x480 x0=0x10004 signed=65540 valid=true
```

So outer `libdexprotector.so` `JNI_OnLoad` returns `JNI_VERSION_1_4` successfully.

#### JNI_OnLoad-only / no Java hook crash test

Created:

```text
hook_jni_onload_no_java_frida17.js
```

This is based on the JNI_OnLoad return-confirm script, but main() intentionally
calls only linker/native hooks and does **not** install any Java hooks:

```text
no provider stub
no AppComponentFactory hook
no GC no-op
no LibApplication.i wrapper
```

Run command:

```bash
./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
  -l hook_jni_onload_no_java_frida17.js
```

Observed log:

```text
[mode] JNI_OnLoad/native-only test: Java hooks disabled
[sub_15DD4 actual] ... out=8ff9a6be expected=8ff9a6be v54_ok=true
[DPMP3 leave] ret=0 byte_8CB48_after=1
[CHAIN leave] sub_55718 ... ret=0 OK
[CHAIN leave] sub_65B50 ... ret=0 OK
[CHAIN leave] sub_51E4C ... ret=0 OK
[CHAIN leave] sub_53390 ... ret=0 OK
[CHAIN leave] sub_51A10 ... ret=0 OK
[CHAIN leave] sub_35BE8 ... ret=0 OK
[outer JNI_OnLoad RETSITE normal] x0=0x10004 signed=65540 valid=true
Process crashed: Bad access due to invalid address
```

Crash with Java hooks removed happens at provider class initialization:

```text
art::InvokeWithVarArgs
-> JNI CallStaticObjectMethod
-> <anonymous loaded dex>
-> ClassLinker::InitializeClass
-> Class_newInstance
-> android.app.AppComponentFactory.instantiateProvider
```

This confirms again that native/JNI_OnLoad completes successfully and the first
post-JNI_OnLoad crash without Java mitigation is Android provider instantiation /
Java class initialization.

## 2026-05-14 — Crash root cause: provider init / bad `ProtectedApplication.s` registration

### Symptom

Running native bypass plus an early Java provider hook:

```bash
frida -U -f com.dexprotector.detector.envchecks \
  -l hook_jni_onload_no_java_frida17.js \
  -l hook_provider_classname_frida17.js
```

crashed before `JNI_OnLoad` returned, around:

```text
[CHAIN enter] sub_35BE8 final_java_callback ...
Process crashed: Bad access due to invalid address
thread: HeapTaskDaemon
libart.so art::CodeInfo::DecodeGcMasksOnly / GC stack walk
```

This was caused by installing Java/Frida hooks too early. `hook_provider_classname_frida17.js` uses `Java.perform`/`Java.use(...).implementation` before hidden `sub_4E354` finishes. During `sub_35BE8` the protector calls back into Java and ART GC can walk through Frida anonymous frames, causing the HeapTaskDaemon crash. The provider hook had not been reached yet.

### Delayed provider probe

Created `hook_provider_classname_after_jni_frida17.js`.

- It installs no Java hooks at load time.
- It only exposes `globalThis.__dpInstallProviderHooksAfterJni()`.
- `hook_jni_onload_no_java_frida17.js` calls this installer from the already-existing outer JNI_OnLoad success return-site (`libdexprotector.so+0x480`) when x0 is `0x10004`/`0x10006`.

This avoids Java hooks during hidden `sub_4E354` / `sub_35BE8`.

### Second crash root cause after JNI_OnLoad

When no early Java hook was active, `JNI_OnLoad` returned successfully but provider init crashed in ART:

```text
outer JNI_OnLoad RETSITE normal x0=0x10004
Process crashed: Bad access
backtrace:
  art::InvokeWithVarArgs<_jmethodID*>
  art::JNI<false>::CallStaticObjectMethod
  art_quick_generic_jni_trampoline
  <anonymous in-memory dex>
  ClassLinker::InitializeClass
  Class_newInstance
  android.app.AppComponentFactory.instantiateProvider
```

The relevant registration before fixing was:

```text
RegisterNatives class="com.dexprotector.detector.envchecks.ProtectedApplication"
  name="s"
  sig="(Ljava/lang/String;)Ljava/lang/String;"
  fn=libart.so+0x61a24c
```

That function pointer is wrong for app native `ProtectedApplication.s(String)`. It points into libart near JNI helper/trampoline code, not the hidden decoder implementation.

Correct implementation is hidden:

```text
ProtectedApplication.s(String) -> hidden+0x56078
```

Patched `hook_jni_onload_no_java_frida17.js` inside the native `JNIEnv->RegisterNatives` trace:

```text
[PATCH reg 0] ProtectedApplication.s fn libart.so+0x61a24c -> hidden+0x56078
```

After patch:

```text
RegisterNatives ProtectedApplication.s -> hidden+0x56078
RegisterNatives ProtectedApplication.ye -> hidden+0x4f9dc
outer JNI_OnLoad RETSITE normal x0=0x10004
```

The delayed provider probe then observed provider initialization succeeding:

```text
[instantiateProvider ENTER] ProtectedAppComponentFactory provider="com.google.firebase.provider.FirebaseInitProvider"
[instantiateProvider ENTER] android.app.AppComponentFactory provider="com.google.firebase.provider.FirebaseInitProvider"
[instantiateProvider LEAVE] android.app.AppComponentFactory ... ret=com.google.firebase.provider.FirebaseInitProvider
[instantiateProvider LEAVE] ProtectedAppComponentFactory ... ret=com.google.firebase.provider.FirebaseInitProvider
```

### Conclusion

There were two separate crash causes:

1. **Early Java provider hook crash:** Java hooks installed before hidden JNI init finished disturbed ART/GC during `sub_35BE8`.
2. **Provider init crash:** `ProtectedApplication.s(String)` was registered with a bad `libart.so+0x61a24c` function pointer. Provider class initialization executes protected/in-memory Java code that needs `ProtectedApplication.s`; the bad native pointer crashes ART. Forcing the registration to `hidden+0x56078` fixes provider instantiation.

Use this command for provider tracing:

```bash
./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
  -l hook_jni_onload_no_java_frida17.js \
  -l hook_provider_classname_after_jni_frida17.js
```

Do not use the old early `hook_provider_classname_frida17.js` together with hidden-init bypass unless diagnosing Java-hook timing crashes.

## 2026-05-14 — `sub_55718` integrity bypass without RegisterNatives fn patch

Goal: stop patching `RegisterNatives` for `ProtectedApplication.s(String)` from `libart.so+0x61a24c` to `hidden+0x56078`, and instead bypass the integrity check that selects the native fn.

### Root cause

`sub_55718` computes/holds a 32-byte value in its local `v45` and compares it with a 32-byte expected value from the `dp.mp3` decompressed payload. The decisive code is:

```asm
0x55a50  ldp x8, x9,  [x29,#-0x98]   ; v45[0..15]
0x55a54  ldp x10,x11, [x20]          ; expected[0..15]
...
0x55a64  ldp x12,x10, [x20,#0x10]    ; expected[16..31]
0x55a74  b.eq 0x55a80                ; compare passed
0x55a78  ldr x9, [x8,#0x390]         ; fail: poison fn = JNIEnv CallStaticObjectMethod
0x55a84  adr x9, 0x56078             ; pass: real ProtectedApplication.s decoder
0x55a8c  stur x9, [x29,#-0xa8]       ; JNINativeMethod.fn
0x55aa4  blr x20                     ; RegisterNatives(env, clazz, &method, 1)
```

If the compare fails, `ProtectedApplication.s(String):String` is registered with `libart.so+0x61a24c` (`JNIEnv->CallStaticObjectMethod`), which later crashes ART/provider initialization. If it passes, it registers the correct hidden native decoder at `hidden+0x56078`.

### Tried and rejected: Frida mid-block hook at `0x55a50`

Initial attempt copied expected bytes into `v45` at `hidden+0x55a50`. It made the first compare pass, but `sub_55718` pivots SP with `mov sp, x1` before this block, so a Frida inline hook there caused re-entry into the `RegisterNatives` block with corrupted stack args:

```text
RegisterNatives #6: ProtectedApplication.s -> hidden+0x56078 OK
RegisterNatives #7: method record garbage, fn=libart.so+0x61a24c, ret=-1
```

So avoid `Interceptor.attach()` inside this stack-pivoted block.

### Stable bypass

Patch the branch instruction instead of patching `RegisterNatives`:

```asm
0x55a74: b.eq 0x55a80   ->   b 0x55a80
```

Frida log:

```text
[sub_55718 integrity branch patch]
0x7408ec5a74: 60000054 -> 03000014 target=0x7408ec5a80
(force real s() decoder; no RegisterNatives fn patch)
```

`RegisterNatives` now naturally sees the correct fn without any `PATCH reg` line:

```text
[JNI RegisterNatives enter #6] caller=hidden+0x55aa8
  class="com.dexprotector.detector.envchecks.ProtectedApplication"
  [reg 0] name="s" sig="(Ljava/lang/String;)Ljava/lang/String;"
          fn=0x7408ec6078 hidden+0x56078
[CHAIN leave] sub_55718 string/native_decoder_setup ret=0x0 signed=0 OK
```

Full test command:

```bash
timeout 60s ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
  -l hook_jni_onload_no_java_frida17.js \
  -l hook_provider_classname_after_jni_frida17.js
```

Evidence from `/tmp/frida_sub55718_branch_bypass_noregpatch_161107.log`:

```text
[outer JNI_OnLoad RETSITE normal] x0=0x10004 signed=65540 valid=true
[instantiateProvider ENTER] ProtectedAppComponentFactory provider="com.google.firebase.provider.FirebaseInitProvider"
[instantiateProvider LEAVE] android.app.AppComponentFactory ... ret=com.google.firebase.provider.FirebaseInitProvider
[instantiateProvider LEAVE] ProtectedAppComponentFactory ... ret=com.google.firebase.provider.FirebaseInitProvider
```

No `Process crashed` / `Bad JNI version` appeared before the timeout ended the Frida session.

### Current script state

`hook_jni_onload_no_java_frida17.js` now has:

```js
const BYPASS_SUB55718_INTEGRITY_COMPARE = true;
```

The old direct `RegisterNatives` writePointer patch for `ProtectedApplication.s` was removed from the trace hook. `RegisterNatives` now only logs method records; the correct `hidden+0x56078` value comes from the patched branch in `sub_55718`.

## 2026-05-14 — Cleaner `sub_55718` bypass: redirect HMAC input to clean snapshot

The branch patch was replaced with the cleaner approach: keep the real compare and make its HMAC input use the clean hidden-image snapshot captured before hidden hooks are installed.

### Why

`sub_55718` computes:

```c
v45 = HMAC_SHA256(key = empty, data = hidden_base, len = 0x7caa0);
if (v45 == *(asset_id_1 + 0x20))
    fn = hidden + 0x56078;
else
    fn = JNIEnv->CallStaticObjectMethod; // poison libart.so+0x61a24c
```

Frida hooks dirty `hidden_base[0:0x7caa0]`, so the HMAC mismatches. We already capture a clean copy early:

```text
[runtime clean hidden snapshot] src=<hidden_base> dst=<runtimeCleanHiddenImageCopy> len=0x7caa0
```

### New hook

Hook `sub_15F44` only for the call from `sub_55718+0x238` / return address `hidden+0x55950`:

```js
if (lr == hidden+0x55950 && key_len == 0 && data == hidden_base && len == 0x7caa0) {
    args[2] = runtimeCleanHiddenImageCopy;
}
```

No branch patch and no `RegisterNatives` fn patch are needed.

### Verified log

Command:

```bash
timeout 50s ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
  -l hook_jni_onload_no_java_frida17.js \
  -l hook_provider_classname_after_jni_frida17.js
```

Evidence from `/tmp/frida_sub55718_clean_snapshot_163216.log`:

```text
[sub_55718 HMAC redirect]
caller=hidden+0x55950 key_len=0
 data 0x7408e74000 -> 0x76aac00010 len=0x7caa0
 expected=7ec8a168455cf863cf5db8e8051068f0f3d0c6288e824dcfb804363c9bfa3729

[sub_55718 HMAC leave]
digest=7ec8a168455cf863cf5db8e8051068f0f3d0c6288e824dcfb804363c9bfa3729
expected=7ec8a168455cf863cf5db8e8051068f0f3d0c6288e824dcfb804363c9bfa3729
match=true

RegisterNatives ProtectedApplication.s(String):String -> hidden+0x56078
[CHAIN leave] sub_55718 ... ret=0 OK
[outer JNI_OnLoad RETSITE normal] x0=0x10004 valid=true
FirebaseInitProvider instantiated successfully
```

This is now the preferred bypass because it preserves the compare semantics: the compare passes because the HMAC is computed over the original clean image.

## 2026-05-14 — Final cleaned bypass script

Created/updated `bypass_dexprotector.js` as the compact working script.

Removed/silenced noisy diagnostics:

- process death / native exception trace hooks
- `sub_5F0D0` CRC internals trace block
- post-DP chain return spam
- non-essential precheck trace hooks
- direct `RegisterNatives` function-pointer patch for `ProtectedApplication.s`

Kept important behavior only:

- outer `sub_918` key spoof
- clean hidden-image snapshot before hidden hooks
- `sub_3E038` digest forced to clean snapshot digest
- `sub_16190` protected-code hash spoof
- watchdog thread spawn block
- minimal `qword_8CEF0` / saved-LR restore
- `ic.dat` decrypt/decompress dump
- `dp.mp3` decrypt/decompress dump
- classes selector hash over clean snapshot
- `sub_55718` HMAC input redirect: `hidden_base -> runtimeCleanHiddenImageCopy`

Verification command:

```bash
timeout 45s ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
  -l bypass_dexprotector.js
```

Evidence from `/tmp/frida_bypass_dexprotector_164107.log`:

```text
[runtime clean hidden snapshot] src=0x7408e7c000 dst=0x76aac00010 len=0x7caa0
[sub_320B4/sub_3E038 force digest #1] ... source=runtime-clean ok=true
[sub_16190 spoof protected] real=0x894e111a2d3a72dc -> 0xfc920bfb67d0075a
[ic.dat decrypt leave] ret=0
[ic.dat decompressed] ...
[DPMP3 hash clean-copy] caller=hidden+0x40460 arg0 0x7408e7c000 -> 0x76aac00010
[DPMP3 hash leave] ... match=true
[sub_55718 HMAC redirect] caller=hidden+0x55950 ... data 0x7408e7c000->0x76aac00010 len=0x7caa0
[sub_55718 HMAC leave] digest=7ec8...3729 expected=7ec8...3729 match=true
[reg 0] name="s" sig="(Ljava/lang/String;)Ljava/lang/String;" fn=... hidden+0x56078
[outer JNI_OnLoad RETSITE normal] x0=0x10004 valid=true
```

No `Bad JNI version`, `Process crashed`, or `FATAL EXCEPTION` appeared before timeout.

## 2026-05-14 — LibApplication.i dispatcher tracing script

Created `trace_libapplication_i_resolver_frida17.js` from `bypass_dexprotector.js`.

Purpose: keep the stable native DexProtector bypass, then after outer `JNI_OnLoad` succeeds, hook all overloads of:

```java
com.dexprotector.detector.envchecks.LibApplication.i(...)
```

The script logs:

- overload signature / return type
- opcode, both signed and hex
- argument classes / primitive values
- return class / primitive value
- nested dispatcher depth

Default mode is intentionally minimal and stable:

```js
const TRACE_LIBAPP_REFLECTION_RESOLVER = false;
const TRACE_LIBAPP_JNI_RESOLVER = false;
const TRACE_LIBAPP_JAVA_STACK = false;
const TRACE_LIBAPP_OBJECT_TOSTRING = false;
```

Reason: stack capture, Java reflection hooks, and JNIEnv hooks can perturb protected class initialization. A short test with JNI resolver enabled exposed useful mappings like:

```text
opcode 0x24a1 / 9377 -> java.lang.System.currentTimeMillis()J
opcode 0x2129 / 8489 -> android.os.SystemClock.elapsedRealtime()J
opcode 0x24d9 / 9433 -> android.os.SystemClock.uptimeMillis()J
opcode 0x63f2 / 25586 -> com.google.firebase.StartupTime.create(JJJ)
```

But full JNI resolver tracing is noisy/fragile, so it is off by default. For a targeted opcode, edit:

```js
const TRACE_LIBAPP_FOCUS_OPCODES = [9320];
const TRACE_LIBAPP_JNI_RESOLVER = true;
const TRACE_LIBAPP_LOG_ALL_CALLS = false;
```

Verification command:

```bash
timeout 30s ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
  -l trace_libapplication_i_resolver_frida17.js
```

Evidence from `/tmp/frida_trace_libapp_i_focuspatch_171842.log`:

```text
[outer JNI_OnLoad RETSITE normal] x0=0x10004 valid=true
[LibApplication.i hook] installed 1176 overload(s)
[LibApplication.i enter #3] sig=long i(int) opcode=0x24a1 (9377)
[LibApplication.i leave #3] ret=1778753924224
[LibApplication.i enter #7] sig=java.lang.Object i(int) opcode=0xffffec16 (-5098)
[LibApplication.i leave #7] ret=com.google.firebase.AutoValue_StartupTime
```

No crash markers were observed before timeout in default minimal mode.

## Dispatcher `LibApplication.i(...)` map opcode như thế nào (2026-05-14)

Đã xác nhận layout của `assets/dp.mp3` sau decrypt/decompress (`dumps/ic_dat_dumps/dp_mp3_decompressed.bin`):

- `u32[0x20] = 0x21af`: số class trong class-offset table.
- `u32[0x24] = 0x12feb`: số dispatcher entry/opcode.
- `entry_table = +0x28`, mỗi entry 16 bytes.
- `class_offset_table = 0x28 + 0x12feb * 0x10 = 0x12fed8`.
- Sau `class_offset_table + 0x21af*4` là string `com/dexprotector/detector/envchecks/LibApplication`; string pool thật bắt đầu sau NUL của string này: `string_pool = +0x1385c7`.

Hidden native setup:

- `sub_41108(env, class_offsets, class_count, entry_table, entry_count, string_pool)` lưu các base vào globals:
  - `qword_8CB58 = entry_table`
  - `dword_8CB50 = entry_count`
  - `qword_8CB70 = class_offset_table`
  - `qword_8CB60 = string_pool`
  - tạo cache `qword_8CB78 = calloc(entry_count, 8)` cho `jfieldID/jmethodID`
  - tạo Java object arrays để cache `jclass` / reflected members.
- `sub_4DDB4` scan `LibApplication.getDeclaredMethods()`, tìm mọi method tên `i`, lấy shorty/proto, rồi `sub_4130C(shorty)` chọn native wrapper theo return type (`I`, `L`, `V`, ...). `sub_35F0C` ghi wrapper pointer vào ArtMethod/native entry.
- Wrapper nhận `opcode` arg đầu. Mask opcode:
  - nếu `opcode >= 0`: index = opcode
  - nếu `opcode <= -9`: index = opcode & 0xffff
  - nếu `-8 <= opcode < 0`: index = opcode & 0xf
- `sub_40638(index, env)` kiểm tra index < `entry_count`, rồi trả về `entry_table + index*16`; nếu out-of-range thì throw exception chứa opcode hex.

Format 1 entry 16 bytes:

```c
struct DpDispatchEntry {
    uint32_t w0;        // bits: flags=w0&0x1f, kind=(w0>>5)&0x1f, class_idx=w0>>10
    uint32_t name_rel;  // string_pool + name_rel
    uint32_t sig_rel;   // string_pool + sig_rel
    uint32_t extra_rel; // thường là shorty/proto, ví dụ IIL/VILL
};
```

Handler selection:

```c
entry = entry_table[index];
kind = (entry.w0 >> 5) & 0x1f;
wrapper_base = base_by_return_type[shorty[0]];
handler = op_handler_table[wrapper_base + kind];
return handler(env, index, va_args);
```

Base wrapper đã thấy:

- `Z`: 3, `B`: 11, `S`: 19, `C`: 27, `I`: 35, `J`: 43, `F`: 51, `D`: 59, `L`: 67, `V`: 78.

Ví dụ đã xác nhận bằng Frida JNI trace:

```text
LibApplication.i(0x114dc, segment) overload int i(int,Object)
entry_off = 0x114de8
raw       = e3e052008a36160092fd0d006cff0d00
w0        = 0x52e0e3 -> flags=3, kind=7, class_idx=5304
class     = com/dexprotector/detector/envchecks/QrGen$Segment
name      = bitLength
sig       = I
extra     = IIL
ret I + kind 7 -> handler_slot 42 -> JNI GetIntField
=> LibApplication.i(0x114dc, segment) == segment.bitLength
```

Tạo helper local: `parse_dp_dispatcher.py`.

Ví dụ:

```bash
./parse_dp_dispatcher.py --ret I 0x114dc
./parse_dp_dispatcher.py --ret V 9320
```

Opcode `9320` map ra:

```text
class="java/security/KeyPairGenerator"
name="initialize"
sig="(Ljava/security/spec/AlgorithmParameterSpec;)V"
extra="VILL"
kind=0, ret=V -> CallVoidMethod-like instance call
```

## classes0 smali dispatcher patcher (2026-05-14)

Created scripts/artifacts for deobfuscating `LibApplication.i(opcode, ...)` in `classes0` using decrypted `dp.mp3`:

- `parse_dp_dispatcher.py`: parse an opcode to class/name/signature/kind/flags.
- `patch_classes0_dispatch.py`: patch baksmali output by replacing supported dispatcher calls with normal smali instructions.
- `CLASSES0_DISPATCH_PATCH_NOTES.md`: commands/results.

Generated smali:

```text
build/classes0_smali/                 # original baksmali output
build/classes0_smali_patched/         # aggressive full direct-call patch; not buildable as single dex due method_id limit
build/classes0_smali_fieldpatched/    # buildable: fields + new-instance only
build/classes0_smali_apppatched/      # buildable: fields + new-instance + app-owned methods
```

Build outputs:

```text
build/out/classes0_fieldpatched.dex
build/out/classes0_apppatched.dex
```

Important limitation: fully replacing every dispatcher method call in `classes0` creates too many direct method references for one DEX (`Unsigned short value out of range: 73567`). Therefore the buildable modes leave most library method dispatcher calls intact, while still replacing field access, new-instance, and optionally app-owned method calls.

Full aggressive patched smali cannot be emitted as one dex because method references exceed the DEX 64K method-id encoding. Added `build_smali_shards.py` to split `build/classes0_smali_patched/` into buildable dex shards:

```text
build/out/classes0_fullpatched_shards/classes0_fullpatched_part00.dex .. part18.dex
```

These 19 shards are the buildable form of the aggressive classes0 dispatch patch.

Update: after adding propagation for opcode aliases (`const vX; move v0, vX`) and temp-register rewrite for high-register `iget`, the aggressive `build/classes0_smali_patched/` now has **0** remaining `LibApplication.i(...)` calls. Single-dex assemble still fails due method-id overflow (`Unsigned short value out of range: 73608`), so the full aggressive build remains the 19-dex sharded output under `build/out/classes0_fullpatched_shards/`.
