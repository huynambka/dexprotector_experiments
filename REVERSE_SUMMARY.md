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
         Final qword_891B0 buffer observed:
         61d5ccc16f7eaa1fdb8d22c0b2b53829152f8fc339d8b57adac470338b297d2c75ba0aa0df4ba4b11a187e81ce3cb1a518c8ea359364a1b31f824453b9f5785a1841527f6d98b2f82c36e6f96d7da3038676beac5a5d098ae71a9fc4ac17a897e6afd8bafbfaa8387b9c1b0e

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

## 24. Mental model

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
