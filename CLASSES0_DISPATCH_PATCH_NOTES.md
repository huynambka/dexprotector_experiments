# classes0 dispatcher patch notes

Goal: deobfuscate `LibApplication.i(opcode, ...)` calls in `classes0` using decrypted `dp.mp3`, then rebuild dex.

## Inputs

- Original dumped dex:
  - `dumps/ic_dat_dumps/classes_dex_dat_00_classes0_from_container.dex`
- Decrypted dispatcher map:
  - `dumps/ic_dat_dumps/dp_mp3_decompressed.bin`

## Tools

Smali/baksmali jars were resolved under:

```bash
tools/tools/m2deps/
```

## Disassemble classes0 to smali

```bash
java -cp 'tools/tools/m2deps/*' org.jf.baksmali.Main disassemble \
  -o build/classes0_smali \
  dumps/ic_dat_dumps/classes_dex_dat_00_classes0_from_container.dex
```

Result:

- `build/classes0_smali/`
- 9004 smali files

## Dispatcher table parser

Helper:

```bash
./parse_dp_dispatcher.py --ret I 0x114dc
```

Important layout:

```text
entry_count=0x12feb
entry_table=0x28
class_offset_table=0x12fed8
string_pool=0x1385c7
```

Entry format:

```c
struct DpDispatchEntry {
    uint32_t w0;        // flags=w0&0x1f, kind=(w0>>5)&0x1f, class_idx=w0>>10
    uint32_t name_rel;
    uint32_t sig_rel;
    uint32_t extra_rel;
};
```

## Patcher

Script:

```text
patch_classes0_dispatch.py
```

Supported replacements:

- `LibApplication.i(...)` field get -> `iget*` / `sget*`
- field set -> `iput*` / `sput*`
- `<new-instance>` pseudo entry -> `new-instance`
- method calls -> `invoke-static`, `invoke-virtual`, `invoke-interface`, `invoke-direct`
- leaves unsupported/unresolved calls unchanged
- preserves a `# dp:` comment with opcode/kind/flags/target info

## Full patch attempt

Command:

```bash
python3 patch_classes0_dispatch.py \
  --in build/classes0_smali \
  --out build/classes0_smali_patched \
  --dp dumps/ic_dat_dumps/dp_mp3_decompressed.bin
```

Report:

```text
calls=277876
fullpatched remaining LibApplication.i calls=0
```

But rebuilding all direct method calls in one dex hits DEX method-id pressure:

```text
Unsigned short value out of range: 73608
```

Reason: replacing dispatcher calls with direct method refs creates too many direct `method_id` references for a single dex.

## Buildable patch mode: fields + new-instance only

Command:

```bash
python3 patch_classes0_dispatch.py --skip-methods \
  --in build/classes0_smali \
  --out build/classes0_smali_fieldpatched \
  --dp dumps/ic_dat_dumps/dp_mp3_decompressed.bin

java -cp 'tools/tools/m2deps/*' org.jf.smali.Main assemble \
  -o build/out/classes0_fieldpatched.dex \
  build/classes0_smali_fieldpatched
```

Result:

```text
build/out/classes0_fieldpatched.dex
remaining LibApplication.i calls: 181712
sha256: 425777f3a997c8812969873ced0b384837950df7e4e8ab5e01f48e5e410f15fb
```

## Buildable patch mode: fields + new-instance + methods owned by app package

Command:

```bash
python3 patch_classes0_dispatch.py \
  --method-owner-prefix com/dexprotector/detector/envchecks \
  --in build/classes0_smali \
  --out build/classes0_smali_apppatched \
  --dp dumps/ic_dat_dumps/dp_mp3_decompressed.bin

java -cp 'tools/tools/m2deps/*' org.jf.smali.Main assemble \
  -o build/out/classes0_apppatched.dex \
  build/classes0_smali_apppatched
```

Result:

```text
build/out/classes0_apppatched.dex
remaining LibApplication.i calls: 181463
```

Example output:

```smali
# dp: opcode=-72 idx=0xffb8 kind=6 flags=6 Lcom/google/firebase/Firebase;->INSTANCELcom/google/firebase/Firebase; extra=VIL
sput-object v2, Lcom/google/firebase/Firebase;->INSTANCE:Lcom/google/firebase/Firebase;

# dp: opcode=-15000 idx=0xc568 kind=15 flags=4 Lkotlin/enums/EnumEntriesList;->entries[Ljava/lang/Enum; extra=VILL
iput-object p1, p0, Lkotlin/enums/EnumEntriesList;->entries:[Ljava/lang/Enum;
```

## Verification commands

```bash
rg -n 'LibApplication;->i\(' build/classes0_smali | wc -l
rg -n 'LibApplication;->i\(' build/classes0_smali_fieldpatched | wc -l
rg -n 'LibApplication;->i\(' build/classes0_smali_apppatched | wc -l

java -cp 'tools/tools/m2deps/*' org.jf.baksmali.Main list classes \
  build/out/classes0_apppatched.dex | head
```

## Aggressive full-patch build workaround: sharded dex set

A single fully-patched dex cannot be emitted because direct method references exceed the DEX 64K method-id limit. To still produce buildable dex artifacts from the aggressive full-patched smali tree, I added a sharded builder:

```text
build_smali_shards.py
```

Command:

```bash
./build_smali_shards.py \
  --in build/classes0_smali_patched \
  --chunk 500
```

Result:

```text
build/out/classes0_fullpatched_shards/classes0_fullpatched_part00.dex
...
build/out/classes0_fullpatched_shards/classes0_fullpatched_part18.dex
build/out/classes0_fullpatched_shards/manifest.txt
```

This builds all classes from `build/classes0_smali_patched/` into 19 dex shards. This is the buildable form of the aggressive patch; to use it in an APK, the shards would need to be integrated as multidex files (`classesN.dex`) with non-overlapping class definitions.

Current aggressive patch now removes all `LibApplication.i` calls from `build/classes0_smali_patched/` (count: 0).
