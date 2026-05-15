# Mổ DexProtector trên `com.dexprotector.detector.envchecks`: từ loader tự chế đến bypass bằng clean snapshot

> Ghi chú phạm vi: bài viết này ghi lại quá trình reverse trong lab/CTF sandbox. Mục tiêu là hiểu cơ chế của `libdexprotector.so`, hidden native image và các check bị Frida làm bẩn, sau đó xây một bypass tối thiểu để quan sát runtime.

## Mở đầu

DexProtector không chỉ “đổi tên class” hay “mã hóa string”. Ở sample này nó dựng cả một chuỗi bootstrap native:

```text
ProtectedApplication.attachBaseContext()
        ↓ System.loadLibrary("dexprotector")
libdexprotector.so .init_array
        ↓ decrypt/decompress/map hidden image
hidden lib / libdp-like image
        ↓ hidden JNI entry sub_4E354(JavaVM*)
RASP + key derivation + asset decrypt + RegisterNatives
        ↓
ProtectedApplication.onCreate() / ye()
```

Điểm thú vị nhất: nhiều check không chỉ kiểm tra môi trường Android, mà còn kiểm tra chính bytes của hidden native image. Vì Frida inline hook sẽ sửa instruction, chỉ cần hook sai thời điểm là key/ctx bị poison, kéo theo decrypt asset fail hoặc crash ART.

Bài viết này viết theo phong cách “reversing diary”: mỗi bước có quan sát, giả thuyết, test, rồi kết luận.

---

## 1. Bắt đúng cửa vào: đừng chỉ nhìn `System.loadLibrary`

Ở Java/JADX, app dùng `ProtectedApplication`. App bình thường không có class này; đây là Application wrapper do protector chèn vào.

`ProtectedApplication.attachBaseContext()` gọi native load, cuối cùng đưa `libdexprotector.so` vào process. Nhưng nếu hook Java quá sớm, ART/GC có thể đi qua frame/trampoline của Frida trong lúc hidden native đang init và crash rất khó đọc. Vì vậy cách ổn định hơn là bám ở native loader.

Script cuối dùng Frida 17 hook `linker64` và `call_constructors()` để bắt lúc linker chuẩn bị chạy constructor của `libdexprotector.so`:

```text
[linker call_constructors] target=.../split_config.arm64_v8a.apk!/lib/arm64-v8a/libdexprotector.so
[libdexprotector.so] base=0x7408f10000
```

Lý do bám ở đây:

- thấy được `.init_array` trước `JNI_OnLoad`,
- lấy được base của outer library đúng lúc,
- hook được unpacker trước khi hidden image được gọi,
- tránh Java hook quá sớm.

---

## 2. Outer loader: `libdexprotector.so` chỉ là stage-0

`libdexprotector.so` là ARM64 shared object stripped. Hai entry quan trọng:

```text
.init_array[0] = base + 0x378
JNI_OnLoad     = base + 0x440
```

### 2.1 Constructor `sub_378`

`sub_378()` chạy trước exported `JNI_OnLoad()`. Nó:

1. gọi syscall/prctl để giảm khả năng dump/debug,
2. parse program headers của chính nó,
3. tìm PT_LOAD thứ 4,
4. gọi unpacker:

```c
sub_2434(base + 0xf630, 0x588d9)
```

5. lưu function pointer trả về vào `off_B230`,
6. lưu status vào `dword_B228`.

Nếu unpack/link fail, exported JNI_OnLoad trả lỗi âm:

```c
if (dword_B228)
    return -dword_B228; // ví dụ -500
```

Đây là lý do ta từng thấy:

```text
java.lang.UnsatisfiedLinkError: Bad JNI version returned ... -500
```

Nó không phải lỗi Java thật. Đó là outer loader báo hidden image unpack/link fail.

### 2.2 Exported `JNI_OnLoad`

Decompile logic:

```c
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    if (dword_B228)
        return -dword_B228;

    ret = off_B230(vm, 0);   // hidden entry
    off_B230 = NULL;

    if (ret)
        return -ret;

    return JNI_VERSION_1_4;  // 0x10004
}
```

Vậy exported `JNI_OnLoad` chỉ là trampoline. Code thật nằm trong hidden image.

---

## 3. Key unpack: `sub_918()` và linker `r_debug->r_brk`

`sub_918()` sinh key 32-byte để decrypt hidden payload. Nó không chỉ dùng constant. Nó trộn cả runtime state của linker:

```text
r_debug -> r_brk -> bytes đầu của rtld_db_dlactivity()
```

Raw VM key quan sát được:

```text
9b85ecd2ebec18cf24758bdd14df3e03b430508aa690a5006ef23f3c8b7d8ca2
```

Logic chính:

```c
key[0]  ^= p[0];
key[4]  ^= p[1];
key[8]  ^= p[2];
key[12] ^= p[3];
```

Trên Pixel test, `r_brk` bắt đầu bằng:

```text
e4 4c 05 14
```

Nhưng nếu Frida/hook làm thay đổi vùng này, key thay đổi và payload không decrypt được. Bypass trong script dùng ý tưởng spoof bytes của một instruction `RET` ARM64:

```text
c0 03 5f d6
```

Key forced cuối:

```text
5b85ecd2e8ec18cf7b758bddc2df3e03b430508aa690a5006ef23f3c8b7d8ca2
```

Log script:

```text
[outer sub_918 spoof_plan]
fixed_used4=c0035fd6
forced_final=5b85ecd2e8ec18cf7b758bddc2df3e03b430508aa690a5006ef23f3c8b7d8ca2
```

---

## 4. Unpack format: decrypt, decompress, tự link

Các hàm đã rename trong IDA:

```text
sub_D4C  -> dp_cipher_ctx_zero
sub_D60  -> dp_cipher_set_key
sub_DAC  -> dp_stream_xor_crypt
sub_1290 -> dp_unpack_payload
sub_1C5C -> lz4_decompress_block
sub_167C -> custom_linker_relocate
sub_2434 -> unpack_map_link_and_run_init
```

`sub_1290()` làm phần “bung” dữ liệu:

1. gọi `sub_918()` lấy key,
2. init stream cipher,
3. decrypt header 36 bytes,
4. `mmap` anonymous memory,
5. decrypt từng chunk,
6. LZ4 decompress vào vùng mmap,
7. checksum chunk,
8. lưu info để `mprotect` sau.

Header 36 bytes sau decrypt:

```text
000009000000000040000000080000006049080000000800008000000040000003000000
```

Các field chính đã map:

```text
map_size_base = 0x90000
bias_delta    = 0
mapped_ptr_1  = load_bias + 0x84960
extra_off     = 0x80000
extra_size    = 0x8000
alignment     = 0x4000
chunk_count   = 3
```

Điểm dễ nhầm: `mmap` chỉ cấp vùng nhớ. Dữ liệu packed chưa “tự nhiên” nằm trong đó. `sub_1290()` decrypt/decompress chunk rồi ghi vào mapping.

---

## 5. Custom linker: hidden image không có ELF header bình thường

Sau khi chunk đã vào memory, `sub_167C()` làm việc của dynamic linker:

```c
sub_167C(dynamic_ptr, load_bias, auxv, r_debug)
```

Nó parse dynamic table:

```text
DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ,
DT_JMPREL, DT_PLTRELSZ, DT_RELR, DT_RELRSZ...
```

Nó resolve `DT_NEEDED` bằng cách walk `r_debug->r_map`. Lib cần:

```text
libc.so
liblog.so
libandroid.so
```

SONAME của hidden image:

```text
libdp.so
```

Sau relocate, nó wipe metadata:

```c
memset(symtab, 0, strtab + strsz - symtab);
```

Nghĩa là dump quá muộn sẽ thiếu relocation/symbol/string table. Nếu muốn decompile dễ hơn, phải dump đúng thời điểm hoặc combine dump sau relocate với metadata từ bản trước relocate.

`sub_2434()` flow cao cấp:

```text
sub_2220()       -> tìm auxv từ /proc/self/stat/environ layout
sub_2358(auxv)  -> tìm r_debug
sub_1290(...)   -> decrypt + decompress hidden payload
sub_167C(...)   -> resolve imports + relocations
sub_15E0(...)   -> restore mprotect
call init_array -> init thật sự chạy
sub_1658(...)   -> seal/protect lại
return fini_array entry -> hidden JNI entry
```

---

## 6. Hidden entry `sub_4E354`: JNI_OnLoad thật

Hidden entry ở:

```text
hidden+0x4E354 = sub_4E354(JavaVM *vm)
```

Nó bắt đầu như JNI_OnLoad thật:

```c
if (vm->GetEnv(vm, &env, JNI_VERSION_1_4))
    return 1201;
```

Sau đó là một chuỗi gate:

```text
sub_374A0(env)  -> cache JNI refs/classes/methods/fields
sub_367A8(env)  -> delay ContentProviders
sub_363F0()     -> SDK/system property checks
sub_5CB1C()     -> watchdog thread #1
sub_5D6F0()     -> watchdog thread #2
sub_3E038(v54)  -> mix hidden image integrity into crypto ctx
sub_16190(...)  -> protected code hash
sub_5E684(v54)  -> ic.dat integrity/decrypt
sub_4EB9C(...)  -> final env gate + Java payload bootstrap
sub_4E7D8(env, code) -> finalizer/error path
```

Nếu code != 0, nó tạo/đẩy `MessageGuardException_...`. Nếu code == 0, `sub_4E7D8` không phải error; nó là success finalizer, register native `ye()V`.

---

## 7. Protector kiểm soát ContentProvider để giữ thứ tự init

`sub_367A8(JNIEnv *env)` thao tác trực tiếp vào Android framework object.

Runtime log cho thấy nó lấy:

```text
AppBindData.providers
ActivityThread.mInitialApplication
ActivityThread.installContentProviders(Context, List)
```

Flow tương đương:

```java
List providers = appBindData.providers;
savedProviders = NewGlobalRef(providers);
appBindData.providers = null;
activityThread.mInitialApplication = application;
cache installContentProviders(Context, List);
```

Tại sao làm vậy?

Android bình thường install ContentProvider trước `Application.onCreate()`. Protector không muốn provider/app code chạy trước khi:

- hidden image đã unpack,
- asset đã decrypt,
- encrypted classes đã load,
- native bridge/string decoder đã register,
- env/integrity checks đã xong.

Nên nó “giữ” provider list lại, clear field `providers`, rồi sau đó tự install lại khi đã an toàn.

---

## 8. `v54`: context/key trung tâm của hidden lib

Trong `sub_4E354`, `v54` là crypto/check context quan trọng. Nó không chỉ từ static key.

Chuỗi tạo/mutate:

```c
sub_15D88(&unk_89799, 32, &byte_8972C, 64, v54);
sub_3CF84(v54);
sub_3DDB8(v54, 1);
v30 = sub_3E038(v54);
sub_16190(...);
sub_15DD4(v54, ...);
```

Ý nghĩa ngắn:

| Hàm | Vai trò |
|---|---|
| `sub_15D88` | init crypto/check context từ static config |
| `sub_3CF84` | mix APK/signing/config material nếu có |
| `sub_3DDB8` | mix thêm 32-bit/static field tùy flag |
| `sub_3E038` | hash hidden image `[hidden_base, hidden_base+0x7caa0)` rồi mix vào ctx |
| `sub_16190` | hash protected code range `hidden+0x10e00..0x771e8` |
| `sub_15DD4` | PRF/check output; không cần spoof nếu `v54` đúng |

Sai lầm ban đầu: hook hidden functions quá sớm. Vì `sub_3E038()` hash chính hidden image, các inline hook làm bytes thay đổi, dẫn đến `v54` sai. Khi `v54` sai, decrypt `ic.dat` fail với error như `714`.

---

## 9. Clean snapshot: bypass ít xâm lấn nhất

Giải pháp cuối không phải “ép branch lung tung”, mà là giữ một bản sạch của hidden image trước khi đặt hook vào nó.

Thời điểm sạch: ngay trước outer `JNI_OnLoad` gọi hidden entry:

```text
outer libdexprotector.so+0x468  BLR hidden_entry
```

Script làm:

```js
runtimeCleanHiddenImageCopy = Memory.alloc(0x7caa0);
Memory.copy(runtimeCleanHiddenImageCopy, hidden_base, 0x7caa0);
```

Log:

```text
[runtime clean hidden snapshot]
src=0x7408e7c000 dst=0x76aac00010 len=0x7caa0
```

Sau đó, với các hash/check dùng `hidden_base`, ta redirect input sang snapshot sạch trong đúng callsite.

Đây là idea giống “đẳng thức hóa”: không phá compare, mà làm cho giá trị được tính bằng đúng giá trị protector mong đợi.

---

## 10. Các bypass chính

### 10.1 `sub_3E038`: force digest sạch

Digest sạch runtime:

```text
fce5f155a916bccade80a9c585c98f55064e0918095592ad4754aea5932a8696
```

Hook `sub_320B4` khi nó được gọi từ `sub_3E038`, sau đó ghi digest sạch vào output.

Log:

```text
[sub_320B4/sub_3E038 force digest #1]
source=runtime-clean ok=true
```

### 10.2 `sub_16190`: spoof hash protected range

Clean hash:

```text
sub_16190(hidden_base + 0x10E00, 0x663E8, zero_key16)
= 0xfc920bfb67d0075a
```

Hook function-level, chỉ spoof đúng call có:

```text
data = hidden+0x10e00
len  = 0x663e8
key  = zero16
```

Log:

```text
[sub_16190 spoof protected]
real=0x894e111a2d3a72dc -> 0xfc920bfb67d0075a
```

### 10.3 Watchdog thread

Hai hàm spawn detached thread:

```text
sub_5CB1C -> pthread_create start=hidden+0x5CB5C
sub_5D6F0 -> pthread_create start=hidden+0x5D730
```

Script block selective `pthread_create` cho đúng start address, trả 0 như spawn thành công nhưng không tạo thread.

Log:

```text
[watchdog BLOCK] pthread_create start=hidden+0x5cb5c ... -> 0
[watchdog BLOCK] pthread_create start=hidden+0x5d730 ... -> 0
```

### 10.4 `qword_8CEF0`: sửa LR bị Frida làm lệch

Hidden code lưu caller LR vào:

```text
qword_8CEF0
```

Sau này `sub_5F0D0()` dùng nó để recover path từ `/proc/self/maps`. Hook Frida có thể làm LR thành trampoline/anonymous address, khiến path lookup fail.

Fix tối thiểu:

```js
qword_8CEF0 = outer_libdexprotector_base + 0x46c;
saved_lr_on_stack = same_value;
```

### 10.5 `sub_5C4A4`: maps/libc/art precheck

Check này nhạy với instrumentation. Script replace nó trả 0:

```text
[precheck SKIP] sub_5C4A4_maps_libc_art_check ret -> 0
```

---

## 11. `ic.dat`: integrity database của APK

Khi `v54` đúng, `sub_5E684(v54)` decrypt/decompress `assets/ic.dat` thành công.

Flow:

```text
sub_54944(6)       -> open "ic.dat"
sub_20754(...)     -> decrypt/auth
sub_71844(...)     -> decompress
sub_5F0D0(...)     -> verify APK/native-lib CRC path
SipHash(CRC array) -> compare expected hash
```

Log:

```text
[ic.dat decrypt leave] ret=0
[ic.dat decrypted] decomp_size=0xd2 comp_size=0x8b
[ic.dat decompress leave] written=0xd2 expected=0xd2
```

Parsed data:

```text
siphash_key16 = d4278b9ed41c9d789b9120c2348f6f3a
expected_hash = 0x2d49e542ca05617a
entry_count   = 10
```

Entries:

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

CRC/SipHash check passed:

```text
expected = 0x2d49e542ca05617a
computed = 0x2d49e542ca05617a
match    = true
```

---

## 12. `classes.dex.dat`: protected DEX container

`assets/classes.dex.dat` không phải một DEX đơn. Nó là container.

Runtime flow:

```text
assets/classes.dex.dat
        ↓ sub_54944(5)
        ↓ sub_3EB6C()
        ↓ sub_3EA28()
classes_dex_dat_decrypted_container.bin
        ↓ parse offset table
classes0.dex
classes1.dex
classes2.dex
```

Dump được:

```text
classes_dex_dat_00_classes0_from_container.dex  size=13186992  magic=dex\n037\0
classes_dex_dat_01_classes1_from_container.dex  size=12999919  magic=dex\n037\0
classes_dex_dat_02_classes2_from_container.dex  size=11255808  magic=dex\n037\0
```

Script không sửa checksum, không patch bytecode, không rebuild. Nó cắt DEX theo `file_size` trong header sau khi protector decrypt/unpack.

Một gate nhỏ ở đây dùng `sub_6A05C(hidden_base, 0x7caa0, 0)` để chọn/load. Với Frida, hash bị sai. Fix là redirect arg0 sang clean snapshot.

Log:

```text
[classes.dex.dat selector clean-copy]
v12=0x4169c1cc97e045b1 v13=0x4169c1cc97e045b1 match=true
```

---

## 13. `dp.mp3`: metadata cho hidden method/field access

Static decode trong `sub_54944` cho thấy id 4 là `dp.mp3`:

```c
case 4: blob = 0x12D1; // "dp.mp3"
case 5: blob = 0x480C; // "classes.dex.dat"
case 6: blob = 0x5F5B; // "ic.dat"
```

`sub_402E0(env, v54, flag)` mở asset id 4:

```text
sub_54944(4, out) -> "dp.mp3"
sub_20754(...)    -> decrypt/auth
sub_71844(...)    -> decompress
```

Decompressed header:

```text
first_qword = 0x4169c1cc97e045b1
u32_20      = 8623
u32_24      = 77803
```

`first_qword` phải match hash sạch của hidden image:

```c
if (sub_6A05C(hidden_base, 0x7caa0, 0) == *(uint64_t *)decompressed)
    byte_8CB48 = 1;
```

Frida làm dirty hidden image, nên hash fail. Fix giống trên: khi call từ `sub_402E0`, redirect data từ `hidden_base` sang clean snapshot.

Log:

```text
[DPMP3 hash clean-copy] caller=hidden+0x40460 arg0 hidden_base -> clean_snapshot
[DPMP3 hash leave] real=0x4169c1cc97e045b1 expected_first_qword=0x4169c1cc97e045b1 match=true
```

Sau đó table install chạy bình thường:

```text
sub_402E0 -> sub_41108(...) -> byte_8CB48 = 1
```

Về mặt behavior, `dp.mp3` là phần quan trọng cho hide-access / native dispatcher: mapping index -> class/method/field/string pool.

---

## 14. `sub_55718`: lỗi `ProtectedApplication.s` không phải do RegisterNatives tự nhiên sai

Đây là điểm cuối thú vị nhất.

`sub_55718()` setup string decoder native:

```text
ProtectedApplication.s(String):String
```

Nó tính HMAC/SHA256-like value:

```c
v45 = HMAC_SHA256(key = empty, data = hidden_base, len = 0x7caa0);
```

Rồi so với expected 32 bytes lấy từ payload `dp.mp3`:

```c
if (v45 == expected)
    fn = hidden + 0x56078;               // real string decoder
else
    fn = JNIEnv->CallStaticObjectMethod; // poison libart.so+0x61a24c

RegisterNatives(env, ProtectedApplication, { "s", sig, fn }, 1);
```

Nếu ta hook hidden image trước đó, HMAC dùng bytes đã bị Frida patch, compare fail. Khi đó `s(String)` bị register vào `libart.so+0x61a24c`, sau này provider/class init gọi `ProtectedApplication.s(...)` thì ART crash.

### Bypass cũ đã bỏ

Có thể patch branch hoặc patch trực tiếp `RegisterNatives` record để `fn=hidden+0x56078`, nhưng cách này xấu:

- dễ làm hỏng stack/register ở mid-block,
- không giữ semantics,
- nếu protector còn check địa chỉ native function thì lại sai.

### Bypass cuối

Hook `sub_15F44` đúng callsite từ `sub_55718`:

```text
caller LR = hidden+0x55950
key_len   = 0
data      = hidden_base
len       = 0x7caa0
```

Chỉ đổi:

```js
args[2] = runtimeCleanHiddenImageCopy;
```

Kết quả:

```text
[sub_55718 HMAC redirect]
caller=hidden+0x55950
key_len=0
data hidden_base -> clean_snapshot
len=0x7caa0

[sub_55718 HMAC leave]
digest=7ec8a168455cf863cf5db8e8051068f0f3d0c6288e824dcfb804363c9bfa3729
expected=7ec8a168455cf863cf5db8e8051068f0f3d0c6288e824dcfb804363c9bfa3729
match=true
```

Và `RegisterNatives` tự nhiên đúng:

```text
name="s"
sig="(Ljava/lang/String;)Ljava/lang/String;"
fn=hidden+0x56078
```

Đây là bypass sạch nhất trong toàn bộ flow: không ép compare, không patch function pointer, chỉ đưa đúng input sạch vào hash.

---

## 15. RegisterNatives map quan trọng

Các native registrations đã quan sát:

```text
ProtectedApplication$ProtectedApplication.AgqpckdwFG()[B -> hidden+0x4f87c
ProtectedApplication.s(String):String                 -> hidden+0x56078
ProtectedApplication$...$QrGen$Segment.xDwEEmqjHh()   -> hidden+0x65ea0
ProtectedApplication$...$QrGen$Segment.Erq(String)    -> hidden+0x65f34
ProtectedApplication.ylGi(Object,String):InputStream  -> hidden+0x5228c
ProtectedApplication.ye()V                            -> hidden+0x4f9dc
```

`sub_4E7D8(env, 0)` là success finalizer register `ye()V`, không nên log nhầm là error.

---

## 16. Final script: `bypass_dexprotector.js`

Script cuối giữ ít hook nhất có thể:

```text
- linker call_constructors hook
- outer sub_918 key spoof
- clean hidden-image snapshot
- sub_3E038 clean digest fix
- sub_16190 protected hash spoof
- watchdog pthread_create block
- qword_8CEF0/saved LR restore
- sub_5C4A4 maps/libc/art precheck skip
- ic.dat decrypt/decompress dump
- dp.mp3 decrypt/decompress dump
- classes.dex.dat selector clean hash
- sub_55718 HMAC input redirect
- RegisterNatives trace tối thiểu
```

Đã bỏ:

```text
- Java provider hooks quá sớm
- crash/death trace spam
- sub_5F0D0 CRC internals spam
- post-chain return spam
- direct RegisterNatives patch cho ProtectedApplication.s
- branch patch trong sub_55718
```

Run:

```bash
timeout 45s ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
  -l bypass_dexprotector.js
```

Evidence cuối:

```text
[runtime clean hidden snapshot] src=0x7408e7c000 dst=0x76aac00010 len=0x7caa0
[sub_320B4/sub_3E038 force digest #1] source=runtime-clean ok=true
[sub_16190 spoof protected] real=0x894e111a2d3a72dc -> 0xfc920bfb67d0075a
[ic.dat decrypt leave] ret=0
[ic.dat decompressed] ...
[DPMP3 hash clean-copy] arg0 hidden_base -> clean_snapshot
[DPMP3 hash leave] match=true
[sub_55718 HMAC redirect] data hidden_base -> clean_snapshot
[sub_55718 HMAC leave] digest=7ec8...3729 expected=7ec8...3729 match=true
[reg 0] name="s" sig="(Ljava/lang/String;)Ljava/lang/String;" fn=... hidden+0x56078
[outer JNI_OnLoad RETSITE normal] x0=0x10004 valid=true
```

Không thấy:

```text
Bad JNI version
Process crashed
FATAL EXCEPTION
```

---

## 17. Bài học rút ra

### 17.1 Hook càng sớm càng không phải càng tốt

Với protector tự hash code page, hook sớm có thể làm bẩn chính dữ liệu dùng để sinh key. Phải tách:

```text
thời điểm clean snapshot
        ↓
thời điểm install hook
        ↓
thời điểm redirect input hash sang snapshot
```

### 17.2 Bypass tốt là làm compare đúng, không phải nhảy qua compare

Các bypass ổn định nhất đều cùng pattern:

```text
original compare vẫn chạy
computed value == expected value
```

Ví dụ:

- `classes.dex.dat` selector hash,
- `dp.mp3` header hash,
- `sub_55718` HMAC.

### 17.3 `qword_8CEF0` là ví dụ về side effect của Frida

Một hook function-level cũng có thể thay LR/caller context đủ để logic `/proc/self/maps` đọc sai path. Không phải crash nào cũng do check detect Frida; đôi khi do chính instrumentation phá calling context.

### 17.4 Java hook trong giai đoạn hidden JNI init rất nguy hiểm

Early `Java.perform()`/provider hook từng làm ART HeapTaskDaemon crash khi GC walk stack. Final script cố ý native-only cho đến khi hidden init xong.

---

## Appendix A — Offset cheat sheet

### Outer `libdexprotector.so`

| Offset | Tên | Ghi chú |
|---:|---|---|
| `0x378` | `.init_array` constructor | chạy unpacker |
| `0x440` | exported `JNI_OnLoad` | trampoline vào hidden entry |
| `0x468` | call hidden entry | clean snapshot point |
| `0x46c` | return after hidden | expected `qword_8CEF0` |
| `0x918` | `sub_918` | derive unpack key |
| `0x167c` | `sub_167C` outer helper | lấy hidden load bias |
| `0xb228` | `dword_B228` | init status |
| `0xb230` | `off_B230` | hidden entry pointer |

### Hidden image

| Offset | Tên/ý nghĩa |
|---:|---|
| `0x4e354` | hidden JNI entry `sub_4E354` |
| `0x4e7d8` | finalizer/error path `sub_4E7D8` |
| `0x5e684` | `ic.dat` check/decrypt/decompress |
| `0x402e0` | `dp.mp3` decrypt/decompress/init |
| `0x3eb6c` | `classes.dex.dat` loader |
| `0x55718` | setup `ProtectedApplication.s` |
| `0x56078` | real `ProtectedApplication.s(String)` decoder |
| `0x65b50` | `QrGen$Segment` JNI setup |
| `0x16190` | protected-code hash helper |
| `0x15f44` | HMAC helper used by `sub_55718` |
| `0x320b4` | SHA/digest helper used by `sub_3E038` |
| `0x6a05c` | hash helper used by dp/classes selectors |
| `0x8cef0` | saved LR / caller address |
| `0x8cef8` | expected clean `sub_16190` hash |
| `0x8cb48` | dp.mp3 table-install success flag |

---

## Appendix B — Liên hệ với các write-up khác

Bài này có cùng tinh thần với hai write-up đã đọc:

- Romain Thomas mô tả DexProtector như một loader nhiều tầng: `libdexprotector.so` decrypt/map hidden `libdp.so`, dùng linker state trong key derivation, asset như `classes.dex.dat`, `dp.mp3`, `ic.dat` giữ vai trò trung tâm.
- Bài Kanxue nhấn mạnh cách tiếp cận thực chiến: không chỉ hook `System.loadLibrary`, mà bám loader/JNI_OnLoad, dump anonymous executable mapping, dùng LR/callsite để khoanh vùng check, và dùng clean text copy để qua integrity check.

Trong sample này, cùng pattern đó xuất hiện rất rõ: mọi thứ ổn định khi ta dừng “patch branch cho qua” và chuyển sang “cho hàm hash nhìn thấy bản text sạch”.

## References

- Romain Thomas, **A Glimpse Into DexProtector**, 2026: <https://www.romainthomas.fr/post/26-01-dexprotector/>
- Kanxue, **从零开始绕过 DexProtector 加固的 Frida 检测**, 2025: <https://bbs.kanxue.com/thread-289170.htm>
