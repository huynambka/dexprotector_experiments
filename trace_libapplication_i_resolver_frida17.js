'use strict';

/*
 * Frida 17.x DexProtector bypass + LibApplication.i resolver tracer for com.dexprotector.detector.envchecks.
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks -l trace_libapplication_i_resolver_frida17.js
 */

/*
 * Frida 17.x: dump DexProtector assets/ic.dat after decrypt and after decompress.
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l trace_libapplication_i_resolver_frida17.js
 *
 * Dumps on device:
 *   /data/data/com.dexprotector.detector.envchecks/files/ic_dat_dumps/
 *
 * Pull example:
 *   adb shell 'run-as com.dexprotector.detector.envchecks ls -l files/ic_dat_dumps'
 *   adb shell 'run-as com.dexprotector.detector.envchecks cat files/ic_dat_dumps/ic_decompressed.bin' > dumps/ic_decompressed.bin
 */

const TARGET_LIB = 'libdexprotector.so';
const TARGET_INIT_RVA = ptr('0x378');

// Outer libdexprotector.so RVAs.
const DP_SUB_918_RVA = ptr('0x918');
const DP_SUB_918_VM_RAW_COPIED_RVA = ptr('0xc98');
const DP_SUB_918_FINAL_RVA = ptr('0xd34');
const DP_SUB_167C_RVA = ptr('0x167c');
const DP_JNI_ONLOAD_RVA = ptr('0x440');
const DP_JNI_ONLOAD_CALL_HIDDEN_RVA = ptr('0x468'); // outer JNI_OnLoad: BLR hidden_entry, LR becomes +0x46c
const DP_JNI_ONLOAD_RET_AFTER_HIDDEN_RVA = ptr('0x46c');
const DP_DWORD_B228_RVA = ptr('0xb228'); // outer init status; if nonzero JNI_OnLoad returns -this
const DP_OFF_B230_RVA = ptr('0xb230');   // hidden entry pointer called by outer JNI_OnLoad
const SPOOF_RBRK_BYTES = [0xc0, 0x03, 0x5f, 0xd6]; // ARM64 RET instruction bytes.
const SPOOF_OUTER_KEY = true;

// Hidden unpacked-image RVAs.
const H_SUB_4E354_RVA = ptr('0x4e354'); // hidden native entry called by ProtectedApplication.ye
const H_SUB_4E7D8_RVA = ptr('0x4e7d8'); // common MessageGuardException/error path: (env, error_code)
const H_QWORD_8CEF0_RVA = ptr('0x8cef0'); // saved caller LR / outer return address
const CS_AFTER_STORE_QWORD_8CEF0 = ptr('0x4e37c'); // after STR X30, [qword_8CEF0]
const H_SUB_5E684_RVA = ptr('0x5e684'); // check_apk_integrity_from_ic_dat(ctx)
const H_SUB_54944_RVA = ptr('0x54944'); // open/read protected asset by id; id 6 = ic.dat
const H_SUB_3EA28_RVA = ptr('0x3ea28'); // decrypt/unpack assets/classes.dex.dat into a container buffer
const H_SUB_6A05C_RVA = ptr('0x6a05c'); // xxHash64-like helper used by sub_3EB6C load selector
const H_SUB_3F158_RVA = ptr('0x3f158'); // load one decrypted classes.dex.dat DEX chunk into ART
const H_SUB_160FC_RVA = ptr('0x160fc'); // derive/decrypt blob from hidden-image digest
const H_SUB_20754_RVA = ptr('0x20754'); // AEAD decrypt/auth helper used by sub_5E684
const H_SUB_320B4_RVA = ptr('0x320b4'); // hash helper used by sub_3E038(hidden_base, 0x7caa0, out, 0)
const H_SUB_71844_RVA = ptr('0x71844'); // inflate/decompress helper used by sub_5E684
const H_SUB_402E0_RVA = ptr('0x402e0'); // dp.mp3 decrypt/decompress/init path
const H_SUB_4E340_RVA = ptr('0x4e340'); // dp.mp3 table installer/helper
const H_SUB_41108_RVA = ptr('0x41108'); // dp.mp3 table installer/helper
const H_SUB_4DDB4_RVA = ptr('0x4ddb4'); // post-dp.mp3 Java/native setup helper
const H_SUB_4E338_RVA = ptr('0x4e338'); // post-dp.mp3 Java/native setup helper
const H_SUB_54B10_RVA = ptr('0x54b10'); // final StackTrace/Throwable helper after dp.mp3 setup
const H_SUB_55718_RVA = ptr('0x55718'); // post-dp string/native s(String) setup
const H_SUB_55718_INTEGRITY_CMP_RVA = ptr('0x55a50'); // inside sub_55718: before v45[0..31] vs dp.mp3 expected[0..31] compare
const H_SUB_55718_STORE_NATIVE_FN_RVA = ptr('0x55a8c'); // inside sub_55718: chosen JNINativeMethod.fn stored
const H_SUB_65B50_RVA = ptr('0x65b50'); // QrGen$Segment native setup
const H_SUB_51E4C_RVA = ptr('0x51e4c'); // AssetManager/openNonAsset hook setup
const H_SUB_53390_RVA = ptr('0x53390'); // protected resource hook setup
const H_SUB_51A10_RVA = ptr('0x51a10'); // optional AssetExtractor setup
const H_SUB_35BE8_RVA = ptr('0x35be8'); // final Java callback
const H_BYTE_8CB48_RVA = ptr('0x8cb48'); // set when dp.mp3 clean-hash check passes
const H_THREAD_5CB5C_RVA = ptr('0x5cb5c'); // watchdog thread start used by sub_5CB1C
const H_THREAD_5D730_RVA = ptr('0x5d730'); // watchdog thread start used by sub_5D6F0
const H_SUB_3601C_RVA = ptr('0x3601c'); // provider/lifecycle init predicate used by sub_4E354
const H_SUB_3662C_RVA = ptr('0x3662c'); // follow-up init predicate used by sub_4E354
const H_SUB_56078_S_DECODER_RVA = ptr('0x56078'); // real ProtectedApplication.s(String) decoder; patch bad registration

// Bypass checks that our Frida hooks disturb before sub_5E684 is reached.
const H_SUB_16190_RVA = ptr('0x16190');
const H_CALLER_RET_AFTER_SUB16190_RVA = ptr('0x4e5e8');
const H_QWORD_8CEF8_RVA = ptr('0x8cef8');
const H_SUB_15DD4_RVA = ptr('0x15dd4');
const H_SUB_15F44_RVA = ptr('0x15f44'); // HMAC-SHA256 helper used by sub_55718 integrity checks
const H_CALLER_RET_AFTER_SUB15DD4_RVA = ptr('0x4e638');
const EXPECTED_MAGIC_4E354 = [0x8f, 0xf9, 0xa6, 0xbe];
const H_PROTECTED_CODE_START_RVA = ptr('0x10e00');
const H_PROTECTED_CODE_END_RVA = ptr('0x771e8');

// Safe call-site RVAs inside sub_4E354. These are in page 0x4c000/0x4e000,
// not in the 0x3e038 self-key scan range. Prefer these over hooking low helper funcs.
const CS_AFTER_SUB3B6D8   = ptr('0x4e424');
const CS_AFTER_SUB363F0   = ptr('0x4e434');
const CS_AFTER_SUB5E38C   = ptr('0x4e468');
const CS_AFTER_SUB63EA8   = ptr('0x4e4b0');
const CS_AFTER_SUB5CB1C   = ptr('0x4e4f0');
const CS_AFTER_SUB5D6F0   = ptr('0x4e4f8');
const CS_AFTER_SUB3601C   = ptr('0x4e514');
const CS_AFTER_SUB3662C   = ptr('0x4e524');
const CS_AFTER_SUB3E038   = ptr('0x4e5c0');
const CS_AFTER_SUB16190   = ptr('0x4e5e8');
const CS_POISON_PATH      = ptr('0x4e5f0');
const CS_AFTER_SUB15DD4   = ptr('0x4e638');
const CS_AFTER_SUB59F40   = ptr('0x4e76c');
const CS_AFTER_SUB36764   = ptr('0x4e78c');
const CS_AFTER_SUB5E684   = ptr('0x4e7a8');
const CS_AFTER_SUB4EB9C   = ptr('0x4e7c8');

// Final gate / post-sub_66B78 tracing. These are call-sites inside sub_4EB9C/sub_4EFB0.
const H_SUB_4EB9C_RVA = ptr('0x4eb9c');
const H_SUB_4EFB0_RVA = ptr('0x4efb0');
const JNI_FROM_REFLECTED_METHOD_OFF = 0x38;
const JNI_FROM_REFLECTED_FIELD_OFF = 0x40;
const JNI_FIND_CLASS_OFF = 0x30;
const JNI_EXCEPTION_OCCURRED_OFF = 0x78;
const JNI_EXCEPTION_CLEAR_OFF = 0x88;
const JNI_NEW_GLOBAL_REF_OFF = 0xa8;
const JNI_GET_METHOD_ID_OFF = 0x108;
const JNI_GET_STATIC_METHOD_ID_OFF = 0x388;
const JNI_CALL_STATIC_VOID_METHOD_OFF = 0x468;
const JNI_GET_STATIC_FIELD_ID_OFF = 0x480;
const JNI_NEW_STRING_UTF_OFF = 0x538;
const JNI_GET_STRING_UTF_CHARS_OFF = 0x548;
const JNI_RELEASE_STRING_UTF_CHARS_OFF = 0x550;
const JNI_NEW_INT_ARRAY_OFF = 0x598;
const JNI_REGISTER_NATIVES_OFF = 0x6b8;
const JNI_EXCEPTION_CHECK_OFF = 0x720;
const JNI_GET_OBJECT_CLASS_OFF = 0xf8;
const JNI_CALL_OBJECT_METHOD_OFF = 0x110;
const JNI_DELETE_LOCAL_REF_OFF = 0xb8;
const JVM_GET_ENV_OFF = 0x30;
const JNI_VERSION_1_4 = 0x00010004;
const JNI_VERSION_1_6 = 0x00010006;
const CS_4EB9C_AFTER_SUB58DF8 = ptr('0x4ebc0');
const CS_4EB9C_AFTER_SUB592A4 = ptr('0x4ebcc');
const CS_4EB9C_AFTER_SUB59764 = ptr('0x4ebd8');
const CS_4EB9C_AFTER_SUB5AFF8 = ptr('0x4ec3c');
const CS_4EB9C_AFTER_SUB59B60 = ptr('0x4ec64');
const CS_4EB9C_AFTER_SUB5B59C = ptr('0x4eca0');
const CS_4EB9C_AFTER_SUB652F8 = ptr('0x4ecc8');
const CS_4EB9C_AFTER_SUB675E8 = ptr('0x4ecfc');
const CS_4EB9C_AFTER_SUB67E44 = ptr('0x4ed0c');
const CS_4EB9C_AFTER_SUB5B5B8 = ptr('0x4ed30');
const CS_4EB9C_AFTER_SUB6531C = ptr('0x4ed58');
const CS_4EB9C_AFTER_SUB5BA64 = ptr('0x4ed88');
const CS_4EB9C_AFTER_SUB67C08 = ptr('0x4edb0');
const CS_4EB9C_AFTER_SUB68738 = ptr('0x4edbc');
const CS_4EB9C_AFTER_SUB5B740 = ptr('0x4ede0');
const CS_4EB9C_AFTER_SUB6539C = ptr('0x4ee04');
const CS_4EB9C_AFTER_SUB54544 = ptr('0x4ee50');
const CS_4EB9C_AFTER_SUB5F5A8 = ptr('0x4ee78');
const CS_4EB9C_AFTER_SUB687B8 = ptr('0x4eedc');
const CS_4EB9C_AFTER_SUB66B78 = ptr('0x4eef4');
const CS_4EB9C_BEFORE_SUB4EFB0 = ptr('0x4ef94');
const CS_4EB9C_AFTER_SUB4EFB0 = ptr('0x4ef98');

const CS_4EFB0_AFTER_SUB4F44C = ptr('0x4f01c');
const CS_4EFB0_AFTER_SUB3EB6C = ptr('0x4f120');
const CS_4EFB0_AFTER_SUB402E0 = ptr('0x4f170');
const CS_4EFB0_AFTER_SUB55718 = ptr('0x4f1b4');
const CS_4EFB0_AFTER_SUB65B50 = ptr('0x4f1cc');
const CS_4EFB0_AFTER_SUB66480 = ptr('0x4f210');
const CS_4EFB0_AFTER_SUB51E4C = ptr('0x4f25c');
const CS_4EFB0_AFTER_SUB53B24 = ptr('0x4f2a0');
const CS_4EFB0_AFTER_SUB53390 = ptr('0x4f2e4');
const CS_4EFB0_AFTER_SUB4FF68 = ptr('0x4f328');
const CS_4EFB0_AFTER_SUB56578 = ptr('0x4f36c');
const CS_4EFB0_AFTER_SUB3A6A0 = ptr('0x4f398');
const CS_4EFB0_AFTER_SUB3A404 = ptr('0x4f3d8');
const CS_4EFB0_AFTER_SUB51A10 = ptr('0x4f3e8');
const CS_4EFB0_AFTER_SUB56134 = ptr('0x4f400');
const CS_4EFB0_AFTER_SUB3E188 = ptr('0x4f418');
const CS_4EFB0_AFTER_SUB35BE8 = ptr('0x4f430');

// Return addresses inside sub_5E684 after each BL.
const RA_AFTER_OPEN_ICDAT = ptr('0x5e6bc');
const RA_AFTER_DECRYPT   = ptr('0x5e7f0');
const RA_AFTER_DECOMP    = ptr('0x5e860');

// CRC/integrity tracing sites.
const H_SUB_5F0D0_RVA = ptr('0x5f0d0'); // build native lib CRC watchlist
const H_SUB_5F46C_RVA = ptr('0x5f46c'); // mmap file and compute CRC32
const CS_5E684_ICDAT_CRC_STORE = ptr('0x5f0b8'); // STR W28, [X21,X8,LSL#2]
const CS_5E684_SIPHASH_COMPARE = ptr('0x5ee54'); // CMP expected, computed
const CS_5E684_AFTER_SUB5F0D0 = ptr('0x5ee6c'); // right after BL sub_5F0D0/build_native_lib_crc_watchlist
const CS_5E684_RETURN_VALUE_GATE = ptr('0x5e6c8'); // common path: MOV W20, W0; then cleanup
const CS_5E684_CLEANUP_BEGIN = ptr('0x5e730'); // cleanup frees globals, then returns W20
const CS_5E684_BEFORE_RET = ptr('0x5e768'); // MOV W0, W20 before epilogue
const CS_5F0D0_MAP_PATH_STRLEN = ptr('0x5f130'); // strlen(mapped outer-lib path)
const CS_5F0D0_AFTER_PATH_STRLEN = ptr('0x5f134');
const CS_5F0D0_AFTER_APK_K_CMP = ptr('0x5f17c');
const CS_5F0D0_SUCCESS_RET0 = ptr('0x5f35c');
const CS_5F0D0_INIT_ZIP_ITER = ptr('0x5f1d0');
const CS_5F0D0_NATIVE_CRC_READ = ptr('0x5f2dc'); // LDR W22, [central_dir_entry,#0x10]
const CS_5F0D0_ERROR_731 = ptr('0x5f1d8'); // MOV W0, #0x2DB
const CS_5F46C_COMPUTED_CRC = ptr('0x5f548'); // after sub_771EC, before compare expected CRC
const CS_5F0D0_SUCCESS_BRANCH = ptr('0x5f360'); // after MOV W0, WZR; branches to epilogue
const CS_5F0D0_EPILOGUE = ptr('0x5f1dc'); // add back stack frame
const CS_5F0D0_RET = ptr('0x5f1fc'); // RET X30

const CS_4E354_AFTER_SUB5E684 = ptr('0x4e7a8'); // after BL sub_5E684 in sub_4E354
const CS_4E354_SUB5E684_OK_CONTINUE = ptr('0x4e7b0'); // reached only if sub_5E684 returned 0
const CS_4E354_BEFORE_SUB4EB9C = ptr('0x4e7c4'); // final BL sub_4EB9C

const DUMP_DIR = '/data/data/com.dexprotector.detector.envchecks/files/ic_dat_dumps';
const BYPASS_PRE_ICDAT_CHECKS = true; // needed because Frida can trip anti-instrumentation checks before sub_5E684.
// Avoid attaching to tiny branch/epilogue instructions inside sub_5F0D0; those hooks are
// fragile and can stop us before the real caller-return trace at sub_5E684+0x5ee6c.
// Disable every PC/callsite hook after sub_5F0D0. For now only test whether
// execution reaches sub_4EB9C by function onEnter.
// For reachability test: no sub_5F0D0 internals/callsite hooks at all.
// Keep only qword_8CEF0 restore, then let execution run to sub_4EB9C onEnter.
// Experimental selector fix:
// Instead of replacing sub_6A05C() return or forcing the branch, take a clean
// snapshot of hidden[0..0x7caa0) before any hidden Interceptor hooks are
// installed.  Later, only for sub_3EB6C's selector hash call, point sub_6A05C's
// data argument at that clean snapshot.  Return value is real sub_6A05C(clean)
// and the original expected field is untouched.  If the protector's expected
// v13 is the clean-image hash, the normal cmp sees v12 == v13.
const FORCE_CLASSES_DAT_HASH_MATCH = true;
const USE_CLEAN_COPY_FOR_CLASSES_SELECTOR_HASH = true;
// [native-only removed] const TRACE_QRSEGMENT_REFLECTION = false; // noisy; keep false after confirming ctor/method list
// [native-only removed] const ENABLE_PREINIT_QRSEGMENT_SPOOF = false; // after dp.mp3 clean-hash table install, let real dispatcher handle <clinit>; old reflection spoof can corrupt ART GC
// [native-only removed] const TRACE_FINAL_JNI_EXCEPTIONCHECK = false; // avoid global ExceptionCheck spam/ART-GC disturbance; enable only when diagnosing pending Java exceptions
const TRACE_FINAL_GATE_NATIVE = false; // no sub_4EB9C/sub_4EFB0/JNI probes; let Java run naturally
// [native-only removed] const TRACE_ORIGINAL_LIBAPP_DISPATCHER = false; // no Java-level LibApplication.i hook; leave dispatcher/original exception behavior intact
const BYPASS_SUB35BE8_CALLBACK = false; // now real sub_35BE8 works after installing semantic LibApplication.i before callback.
// [native-only removed] const INSTALL_LIBAPP_BEFORE_SUB35BE8_CALLBACK = false; // TEST: dispatcher bypass disabled; let real LibApplication.i path fail/log
const DETACH_ALL_BEFORE_SUB35BE8_CALLBACK = false; // execute sub_35BE8/R$string.a(Context) after removing Frida Interceptor trampolines; avoids ART GC stack-walk crash
const FORCE_CLEAN_SUB3E038_DIGEST = true;
const BYPASS_SUB16190_COMPARE = false; // do not hook mid-block 0x4e5e8; fragile on this custom image.
const BYPASS_SUB16190_FUNC = true;     // hook sub_16190 function after sub_3E038 and spoof only protected-code hash.
const BYPASS_SUB55718_INTEGRITY_COMPARE = true; // make ProtectedApplication.s integrity compare pass naturally.
const CLEAN_SUB3E038_HASH_LEN = 0x7caa0;
// [native-only removed] const ENABLE_JAVA_CRASH_LOGGER = false; // no Java hooks in this test
// Do not hook System.loadLibrary by default: it is @CallerSensitive, and a Java
// wrapper changes the caller/classloader, making split APK libs (e.g. libalice.so)
// fail to resolve even though the original call works.
// [native-only removed] const STUB_PROVIDERS_FOR_SURVIVAL = false; // real provider works after installing semantic LibApplication hook before provider instantiation
// [native-only removed] const STUB_ACTIVITIES_FOR_SURVIVAL = false; // experiment: let real MainActivity instantiate through stock AppComponentFactory
// [native-only removed] const USE_DEX_UI_UPDATER = false; // optional compiled Java updater; disabled until verified on device
// [native-only removed] const DEX_UI_UPDATER_PATH = '/data/local/tmp/dp_ui_updater.dex';
// [native-only removed] const ENABLE_PERIODIC_UI_UPDATER = false; // periodic Frida-side QR updates can still trigger ART/Frida GC Trace/BPT; keep one-shot stable
// [native-only removed] const TRACE_SYSTEM_LOADLIBRARY = false;
// [native-only removed] const SUPPRESS_TPOZ_THROW = true; // debug: log ProtectedApplication$KeystoreUtils.tpoz(ctx, Throwable); optionally swallow
const FORCE_OUTER_JNI_ONLOAD_SUCCESS = false; // debug only: force hidden ret=0 at outer+0x46c so ART gets JNI_VERSION_1_4.
// Avoid mid-block hooks at hidden+0x4e514/0x4e524. hidden+0x4e524 is only 8 bytes before
// loc_4E52C, and Frida's inline trampoline can collide with the final branch target.
const BYPASS_SUB3601C_3662C_BY_FUNCTION = true;
// sub_4E7D8(code=0) can cause the protected init flow to touch sub_5E684 again with a
// transient/half-clean context. First sub_5E684 already verifies and loads ic.dat, so skip
// later duplicate calls to avoid the failing AEAD cleanup/free path.
const SKIP_SUB5E684_AFTER_FIRST_SUCCESS = true;
// [native-only removed] const DUMP_LIBAPP_ARTMETHODS = false; // debug: compare original ArtMethod native slots before semantic override
const WRAP_SUB5E684_WITH_ORIGINAL = true;
// On the success-return path sub_4E354 calls sub_4E7D8(env, 0). Under Frida this callback
// re-enters later init code with stale registers/stack and causes a duplicate sub_5E684/sub_4EB9C.
// The work is already done by sub_4EB9C, so make the code==0 callback a no-op.
const NOOP_SUB4E7D8_CODE0 = false;
// Fallback only. Preferred value is computed at runtime before installing hidden hooks.
const CLEAN_SUB3E038_DIGEST_HEX = '949589497da12b8da29b5dcb375c1bee1045fcf8c474cadb9404d21e8259d078';

const hooked = new Set();
const installedOuterBases = new Set();
const installedHiddenBases = new Set();
const blockedWatchdogThreadStarts = {};
let pthreadCreateBlockerInstalled = false;
let pthreadDetachZeroBlockerInstalled = false;
let hiddenBase = null;
let pendingHiddenLoadBias = null;
let runtimeCleanSub3E038DigestBytes = null;
let runtimeCleanSub16190Hash = null;
let runtimeCleanHiddenImageCopy = null;
let sub16190FuncHookInstalled = false;
let sub5e684HadSuccess = false;
const outerJniOnLoadReturnByTid = {};
let outerHiddenReturnAddress = null;
let seq = 0;
let crashTraceInstalled = false;

const IMPORTANT_LOG_PATTERNS = [
  '[start]', '[linker call_constructors]', `[${TARGET_LIB}]`,
  '[outer sub_918 spoof_plan]', '[outer JNI_OnLoad hidden call]', '[outer JNI_OnLoad RETSITE normal]',
  '[runtime clean hidden snapshot]', '[runtime clean sub_3E038 digest]', '[runtime clean sub_16190]',
  '[watchdog BLOCK]', '[sub_320B4/sub_3E038 force digest', '[sub_16190 spoof protected]',
  '[precheck SKIP]', '[sub_15DD4 actual]',
  '[ic.dat decrypt', '[ic.dat decrypted]', '[ic.dat decompress', '[ic.dat decompressed]', '[ic.dat parsed]', '[ic.dat first names]',
  '[DPMP3 decrypt', '[DPMP3 decrypted]', '[DPMP3 decompress', '[DPMP3 decompressed]', '[DPMP3 hash clean-copy]', '[DPMP3 hash leave]',
  '[classes.dex.dat selector clean-copy]', '[sub_55718 HMAC',
  'RegisterNatives', 'name="s"', 'hidden+0x56078',
  '[LibApplication.i', '[LibApp resolver', '[JNI resolver', '[Reflect resolver',
  '[dump]'
];
function log(s) {
  s = String(s);
  for (const pat of IMPORTANT_LOG_PATTERNS) {
    if (s.indexOf(pat) !== -1) { console.log(s); return; }
  }
}
function warn(s) { console.warn(String(s)); }

function hexBytes(bytes) {
  if (bytes === null) return '<read failed>';
  return bytes.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

function bytesEq(a, b) {
  if (a === null || b === null || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if ((a[i] & 0xff) !== (b[i] & 0xff)) return false;
  }
  return true;
}

function hexToBytes(s) {
  const clean = s.replace(/[^0-9a-fA-F]/g, '');
  if ((clean.length & 1) !== 0) throw new Error(`odd hex length: ${clean.length}`);
  const out = [];
  for (let i = 0; i < clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
  return out;
}

function readBytes(p, len) {
  try {
    if (!p || p.isNull() || len <= 0) return null;
    const ab = p.readByteArray(len);
    if (ab === null) return null;
    return Array.from(new Uint8Array(ab));
  } catch (_) { return null; }
}

function readU32Safe(p) {
  try { return p.readU32() >>> 0; } catch (_) { return null; }
}

function fmtU32(v) {
  if (v === null || v === undefined) return '<err>';
  return '0x' + (v >>> 0).toString(16).padStart(8, '0');
}

function bytesToAscii(bs) {
  if (bs === null) return '<read failed>';
  let s = '';
  for (let i = 0; i < bs.length; i++) {
    const c = bs[i] & 0xff;
    s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
  }
  return s;
}

function readAsciiLen(p, len) {
  if (!p || p.isNull() || len <= 0) return '';
  return bytesToAscii(readBytes(p, Math.min(len, 4096)));
}

function writeBytes(p, bytes) {
  const u8 = new Uint8Array(bytes);
  p.writeByteArray(u8.buffer);
}

function tryWriteBytes(p, bytes) {
  try { writeBytes(p, bytes); return true; } catch (_) { return false; }
}

function readU64Ptr(addr) {
  try { return addr.readPointer(); } catch (_) { return null; }
}

function rDebugInfo(rdebug) {
  const out = {
    rdebug,
    rbrk: ptr(0),
    raw16: '<unread>',
    skipBti: false,
    usedPtr: ptr(0),
    used4: null,
    err: null,
  };

  try {
    if (rdebug === null || rdebug === undefined || rdebug.isNull()) {
      out.err = 'r_debug is NULL';
      return out;
    }

    out.rbrk = rdebug.add(0x10).readPointer();
    out.usedPtr = out.rbrk;
    const raw16 = readBytes(out.rbrk, 16);
    out.raw16 = hexBytes(raw16);

    const firstInsn = out.rbrk.readU32() >>> 0;
    if (firstInsn === 0xd503245f) { // ARM64 BTI C: 5f 24 03 d5
      out.skipBti = true;
      out.usedPtr = out.rbrk.add(4);
    }

    out.used4 = readBytes(out.usedPtr, 4);
  } catch (e) {
    out.err = String(e);
  }

  return out;
}

function keyWithRBrkXor(rawKey, info) {
  if (rawKey === null || info === null || info.used4 === null) return null;
  const out = rawKey.slice();
  out[0]  ^= info.used4[0];
  out[4]  ^= info.used4[1];
  out[8]  ^= info.used4[2];
  out[12] ^= info.used4[3];
  return out;
}

function keyWithFixedRBrkXor(rawKey) {
  if (rawKey === null) return null;
  const out = rawKey.slice();
  out[0]  ^= SPOOF_RBRK_BYTES[0];
  out[4]  ^= SPOOF_RBRK_BYTES[1];
  out[8]  ^= SPOOF_RBRK_BYTES[2];
  out[12] ^= SPOOF_RBRK_BYTES[3];
  return out;
}

function safeCString(p) {
  try { if (!p || p.isNull()) return null; return p.readCString(); } catch (_) { return null; }
}

function findExport(name) {
  if (typeof Module.findExportByName === 'function') return Module.findExportByName(null, name);
  if (typeof Module.getGlobalExportByName === 'function') {
    try { return Module.getGlobalExportByName(name); } catch (_) { return null; }
  }
  return null;
}

function installWatchdogThreadBlocker(loadBias) {
  const starts = [
    [loadBias.add(H_THREAD_5CB5C_RVA), 'sub_5CB5C spawned by sub_5CB1C'],
    [loadBias.add(H_THREAD_5D730_RVA), 'sub_5D730 spawned by sub_5D6F0'],
  ];

  starts.forEach(([addr, label]) => {
    blockedWatchdogThreadStarts[addr.toString()] = label;
  });

  // Block only these two protector watchdog start_routines. Other app/system threads still go through.
  if (!pthreadCreateBlockerInstalled) {
    const pCreate = findExport('pthread_create');
    if (pCreate === null) {
      warn('[watchdog BLOCK] pthread_create export not found; watchdog threads may still spawn');
    } else {
      const realPthreadCreate = new NativeFunction(pCreate, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
      Interceptor.replace(pCreate, new NativeCallback(function (threadPtr, attr, startRoutine, arg) {
        const label = blockedWatchdogThreadStarts[startRoutine.toString()];
        if (label !== undefined) {
          try {
            // Caller will still call pthread_detach(tid). Give it fake tid=0 and make detach(0) harmless below.
            if (!threadPtr.isNull()) threadPtr.writePointer(ptr(0));
          } catch (_) {}
          log(`[watchdog BLOCK] pthread_create start=${moduleDesc(startRoutine)} ${label} arg=${arg} -> 0 (not spawned)`);
          return 0;
        }
        return realPthreadCreate(threadPtr, attr, startRoutine, arg);
      }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
      pthreadCreateBlockerInstalled = true;
      log(`[hooked] pthread_create selective watchdog blocker @ ${pCreate}`);
    }
  }

  // Safety: sub_5CB1C/sub_5D6F0 call pthread_detach(tid) after pthread_create success.
  // If tid is our fake 0, swallow it. Real detach calls still go through.
  if (!pthreadDetachZeroBlockerInstalled) {
    const pDetach = findExport('pthread_detach');
    if (pDetach === null) {
      warn('[watchdog BLOCK] pthread_detach export not found; fake tid=0 detach will use real libc');
    } else {
      const realPthreadDetach = new NativeFunction(pDetach, 'int', ['pointer']);
      Interceptor.replace(pDetach, new NativeCallback(function (tid) {
        if (tid.isNull()) {
          log('[watchdog BLOCK] pthread_detach fake tid=0 -> 0');
          return 0;
        }
        return realPthreadDetach(tid);
      }, 'int', ['pointer']));
      pthreadDetachZeroBlockerInstalled = true;
      log(`[hooked] pthread_detach fake-zero blocker @ ${pDetach}`);
    }
  }
}

function mkdirOne(path) {
  try {
    const p = findExport('mkdir');
    if (p === null) return false;
    const mkdir = new NativeFunction(p, 'int', ['pointer', 'int']);
    mkdir(Memory.allocUtf8String(path), 0x1c0); // 0700
    return true;
  } catch (_) { return false; }
}

function dumpMemoryToFile(name, addr, len) {
  mkdirOne(DUMP_DIR);
  const path = `${DUMP_DIR}/${name}`;
  const ab = addr.readByteArray(len);
  if (ab === null) throw new Error(`readByteArray null @ ${addr} len=0x${len.toString(16)}`);
  const f = new File(path, 'wb');
  try { f.write(ab); f.flush(); }
  finally { f.close(); }
  log(`[dump] ${name} addr=${addr} len=0x${len.toString(16)} -> ${path}`);
}

function dumpPreview(tag, addr, len) {
  const n = Math.min(len, 0x80);
  const b = readBytes(addr, n);
  log(`[${tag}] first_${n}=${hexBytes(b)}`);
}

function attachOnce(addr, label, handlers) {
  const k = `${label}@${addr}`;
  if (hooked.has(k)) return;
  try {
    Interceptor.attach(addr, handlers);
    hooked.add(k);
    log(`[hooked] ${label} @ ${addr}`);
  } catch (e) {
    warn(`[hook FAIL] ${label} @ ${addr}: ${e}`);
  }
}

function getJniFn(env, off) {
  return env.readPointer().add(off).readPointer();
}

function installRegisterNativesTraceFromJvm(jvm, source) {
  try {
    if (!jvm || jvm.isNull()) return;
    const table = jvm.readPointer();
    const getEnvPtr = table.add(JVM_GET_ENV_OFF).readPointer();
    const getEnv = new NativeFunction(getEnvPtr, 'int', ['pointer', 'pointer', 'int']);
    const out = Memory.alloc(Process.pointerSize);
    out.writePointer(ptr(0));

    let rc = getEnv(jvm, out, JNI_VERSION_1_4);
    if (rc !== 0 || out.readPointer().isNull()) {
      out.writePointer(ptr(0));
      rc = getEnv(jvm, out, JNI_VERSION_1_6);
    }

    const env = out.readPointer();
    if (rc !== 0 || env.isNull()) {
      warn(`[JNI RegisterNatives trace] GetEnv failed source=${source} vm=${jvm} rc=${rc} env=${env}`);
      return;
    }
    installRegisterNativesTraceFromEnv(env, `${source} vm=${jvm}`);
  } catch (e) {
    warn(`[JNI RegisterNatives trace] install from JavaVM failed source=${source}: ${e}`);
  }
}

function tryReadJStringUtf(env, jstr) {
  if (!jstr || jstr.isNull()) return null;
  let cstr = ptr(0);
  try {
    const getStringUTFChars = new NativeFunction(getJniFn(env, JNI_GET_STRING_UTF_CHARS_OFF), 'pointer', ['pointer', 'pointer', 'pointer']);
    const releaseStringUTFChars = new NativeFunction(getJniFn(env, JNI_RELEASE_STRING_UTF_CHARS_OFF), 'void', ['pointer', 'pointer', 'pointer']);
    cstr = getStringUTFChars(env, jstr, ptr(0));
    if (!cstr || cstr.isNull()) return null;
    const s = safeCString(cstr);
    releaseStringUTFChars(env, jstr, cstr);
    return s;
  } catch (_) {
    try {
      if (cstr && !cstr.isNull()) {
        const releaseStringUTFChars = new NativeFunction(getJniFn(env, JNI_RELEASE_STRING_UTF_CHARS_OFF), 'void', ['pointer', 'pointer', 'pointer']);
        releaseStringUTFChars(env, jstr, cstr);
      }
    } catch (_) {}
    return null;
  }
}

function tryGetJClassName(env, clazz) {
  // Best-effort, native-only JNI inspection. No high-level Java API hooks.
  if (!env || env.isNull() || !clazz || clazz.isNull()) return null;
  try {
    const exceptionCheck = new NativeFunction(getJniFn(env, JNI_EXCEPTION_CHECK_OFF), 'uchar', ['pointer']);
    if (exceptionCheck(env) !== 0) return '<pending-exception-before-class-name>';

    const getObjectClass = new NativeFunction(getJniFn(env, JNI_GET_OBJECT_CLASS_OFF), 'pointer', ['pointer', 'pointer']);
    const getMethodID = new NativeFunction(getJniFn(env, JNI_GET_METHOD_ID_OFF), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    const callObjectMethod = new NativeFunction(getJniFn(env, JNI_CALL_OBJECT_METHOD_OFF), 'pointer', ['pointer', 'pointer', 'pointer']);
    const deleteLocalRef = new NativeFunction(getJniFn(env, JNI_DELETE_LOCAL_REF_OFF), 'void', ['pointer', 'pointer']);
    const exceptionClear = new NativeFunction(getJniFn(env, JNI_EXCEPTION_CLEAR_OFF), 'void', ['pointer']);

    const classClass = getObjectClass(env, clazz); // clazz itself is a java.lang.Class object.
    if (!classClass || classClass.isNull()) return null;
    const mid = getMethodID(env, classClass, Memory.allocUtf8String('getName'), Memory.allocUtf8String('()Ljava/lang/String;'));
    if (!mid || mid.isNull()) {
      if (exceptionCheck(env) !== 0) exceptionClear(env);
      try { deleteLocalRef(env, classClass); } catch (_) {}
      return null;
    }
    const nameObj = callObjectMethod(env, clazz, mid);
    let name = tryReadJStringUtf(env, nameObj);
    if (exceptionCheck(env) !== 0) {
      exceptionClear(env);
      name = name || '<exception-while-reading-class-name>';
    }
    try { if (nameObj && !nameObj.isNull()) deleteLocalRef(env, nameObj); } catch (_) {}
    try { deleteLocalRef(env, classClass); } catch (_) {}
    return name;
  } catch (e) {
    return `<class-name-failed: ${e}>`;
  }
}

function installRegisterNativesTraceFromEnv(env, source) {
  try {
    if (!env || env.isNull()) return;
    const registerNatives = getJniFn(env, JNI_REGISTER_NATIVES_OFF);
    const label = `JNI RegisterNatives full trace (${source})`;
    attachOnce(registerNatives, label, {
      onEnter(args) {
        this.id = ++seq;
        this.env = args[0];
        this.clazz = args[1];
        this.methods = args[2];
        this.count = u64ToSafeNumber(args[3]);
        this.caller = moduleDesc(this.context.lr);
        this.className = tryGetJClassName(this.env, this.clazz);
        log(`\n[JNI RegisterNatives enter #${this.id}] caller=${this.caller}`);
        log(`  env=${this.env} clazz=${this.clazz} class=${JSON.stringify(this.className)} methods=${this.methods} count=${this.count}`);
        const max = Math.min(this.count, 128);
        for (let i = 0; i < max; i++) {
          const rec = this.methods.add(i * Process.pointerSize * 3);
          let namePtr = ptr(0), sigPtr = ptr(0), fn = ptr(0);
          let name = null, sig = null;
          try { namePtr = rec.readPointer(); name = safeCString(namePtr); } catch (_) {}
          try { sigPtr = rec.add(Process.pointerSize).readPointer(); sig = safeCString(sigPtr); } catch (_) {}
          try { fn = rec.add(Process.pointerSize * 2).readPointer(); } catch (_) {}
          log(`  [reg ${i}] name_ptr=${namePtr} name=${JSON.stringify(name)} sig_ptr=${sigPtr} sig=${JSON.stringify(sig)} fn=${fn} ${moduleDesc(fn)}`);
        }
        if (this.count > max) log(`  ... truncated ${this.count - max} methods`);
      },
      onLeave(retval) {
        log(`[JNI RegisterNatives leave #${this.id}] ret=${retval} signed=${retval.toInt32()} class=${JSON.stringify(this.className)}`);
      }
    });
  } catch (e) {
    warn(`[JNI RegisterNatives trace] install from env failed source=${source} env=${env}: ${e}`);
  }
}

function replaceOnce(addr, label, callback) {
  const k = `replace:${label}@${addr}`;
  if (hooked.has(k)) return;
  try {
    Interceptor.replace(addr, callback);
    hooked.add(k);
    log(`[replaced] ${label} @ ${addr}`);
  } catch (e) {
    warn(`[replace FAIL] ${label} @ ${addr}: ${e}`);
  }
}

function shortBacktrace(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .slice(0, 8)
      .map(a => moduleDesc(a))
      .join(' <- ');
  } catch (e) {
    return `<bt failed: ${e}>`;
  }
}

// [native-only] Removed installJavaCrashLogger Java/JNI diagnostic hook block.

function moduleDesc(p) {
  try {
    const m = Process.findModuleByAddress(p);
    if (m !== null) return `${m.name}+0x${p.sub(m.base).toString(16)}`;
  } catch (_) {}
  if (hiddenBase !== null) {
    try {
      const off = p.sub(hiddenBase);
      if (off.compare(ptr(0)) >= 0 && off.compare(ptr('0x1000000')) < 0) return `hidden+0x${off.toString(16)}`;
    } catch (_) {}
  }
  return String(p);
}

function ptrEq(a, b) {
  try { return a.compare(b) === 0; } catch (_) { return false; }
}

// [native-only] Removed dumpArtMethodsForLibApp Java/JNI diagnostic hook block.

function u64ToSafeNumber(v) {
  try {
    const n = v.toNumber();
    if (Number.isSafeInteger(n)) return n;
  } catch (_) {}
  try { return v.toUInt32(); } catch (_) {}
  return -1;
}

function findLinkerModule() {
  const want = Process.pointerSize === 8 ? 'linker64' : 'linker';
  const mods = Process.enumerateModules();
  return mods.find(m => m.name === want) ||
         mods.find(m => /\/(linker64|linker)$/.test(m.path)) ||
         mods.find(m => m.name.indexOf('linker') !== -1 || m.path.indexOf('/linker') !== -1);
}

function enumSymbols(m) {
  if (m && typeof m.enumerateSymbols === 'function') return m.enumerateSymbols();
  if (typeof Module.enumerateSymbolsSync === 'function') return Module.enumerateSymbolsSync(m.name);
  if (typeof Module.enumerateSymbols === 'function') return Module.enumerateSymbols(m.name);
  throw new Error('No symbol enumeration API available');
}

function isTargetPath(s) {
  return s !== null && s.indexOf(TARGET_LIB) !== -1;
}

function findTargetModule(path) {
  let m = Process.findModuleByName(TARGET_LIB);
  if (m !== null) return m;
  return Process.enumerateModules().find(x => x.path === path || x.path.indexOf(TARGET_LIB) !== -1 || x.name === TARGET_LIB) || null;
}

function snapshotRuntimeCleanHiddenImage(loadBias) {
  if (runtimeCleanHiddenImageCopy !== null) return runtimeCleanHiddenImageCopy;
  try {
    runtimeCleanHiddenImageCopy = Memory.alloc(CLEAN_SUB3E038_HASH_LEN);
    Memory.copy(runtimeCleanHiddenImageCopy, loadBias, CLEAN_SUB3E038_HASH_LEN);
    log(`[runtime clean hidden snapshot] src=${loadBias} dst=${runtimeCleanHiddenImageCopy} len=0x${CLEAN_SUB3E038_HASH_LEN.toString(16)}`);
  } catch (e) {
    runtimeCleanHiddenImageCopy = null;
    warn(`[runtime clean hidden snapshot] failed: ${e}`);
  }
  return runtimeCleanHiddenImageCopy;
}

function computeRuntimeCleanSub3E038Digest(loadBias) {
  if (!FORCE_CLEAN_SUB3E038_DIGEST) return null;
  if (runtimeCleanSub3E038DigestBytes !== null) return runtimeCleanSub3E038DigestBytes;

  try {
    // Important: called from outer sub_167C onLeave, before any hidden-code Interceptor.attach().
    // Read/execute clean hidden code, no inline patch inside hidden image yet.
    snapshotRuntimeCleanHiddenImage(loadBias);
    const out = Memory.alloc(32);
    const hashFn = new NativeFunction(
      loadBias.add(H_SUB_320B4_RVA),
      'int',
      ['pointer', 'ulong', 'pointer', 'pointer']
    );
    const ret = hashFn(loadBias, CLEAN_SUB3E038_HASH_LEN, out, ptr(0));
    const digest = readBytes(out, 32);
    if (digest !== null) {
      runtimeCleanSub3E038DigestBytes = digest;
      log(`[runtime clean sub_3E038 digest] ret=${ret} data=${loadBias} len=0x${CLEAN_SUB3E038_HASH_LEN.toString(16)} digest=${hexBytes(digest)}`);
    } else {
      warn('[runtime clean sub_3E038 digest] read digest failed; fallback static digest will be used');
    }
  } catch (e) {
    warn(`[runtime clean sub_3E038 digest] compute failed: ${e}; fallback static digest will be used`);
  }

  return runtimeCleanSub3E038DigestBytes;
}

function computeRuntimeCleanSub16190Hash(loadBias) {
  if (!BYPASS_SUB16190_FUNC) return null;
  if (runtimeCleanSub16190Hash !== null) return runtimeCleanSub16190Hash;

  try {
    // Clean point: outer JNI_OnLoad before hidden sub_4E354 runs, before hidden hooks.
    const key = Memory.alloc(16);
    key.writeByteArray(new Uint8Array(16).buffer);

    const start = loadBias.add(H_PROTECTED_CODE_START_RVA);
    const len = H_PROTECTED_CODE_END_RVA.sub(H_PROTECTED_CODE_START_RVA).toUInt32();
    const siphash = new NativeFunction(
      loadBias.add(H_SUB_16190_RVA),
      'pointer',
      ['pointer', 'ulong', 'pointer']
    );

    runtimeCleanSub16190Hash = siphash(start, len, key);
    log(`[runtime clean sub_16190] data=${start} len=0x${len.toString(16)} key=zero16 hash=${runtimeCleanSub16190Hash}`);
  } catch (e) {
    warn(`[runtime clean sub_16190] compute failed: ${e}; will use qword_8CEF8 if available`);
  }

  return runtimeCleanSub16190Hash;
}

function installSub16190FunctionSpoof(loadBias, onSpoof) {
  if (!BYPASS_SUB16190_FUNC) return;
  if (sub16190FuncHookInstalled) return;

  const expected = runtimeCleanSub16190Hash || readU64Ptr(loadBias.add(H_QWORD_8CEF8_RVA));
  if (expected === null) {
    warn('[sub_16190 func spoof] no expected hash available');
    return;
  }

  const targetData = loadBias.add(H_PROTECTED_CODE_START_RVA);
  const targetLen = H_PROTECTED_CODE_END_RVA.sub(H_PROTECTED_CODE_START_RVA).toUInt32();
  const addr = loadBias.add(H_SUB_16190_RVA);

  Interceptor.attach(addr, {
    onEnter(args) {
      this.data = args[0];
      this.len = u64ToSafeNumber(args[1]);
      this.key = args[2];
      this.match = ptrEq(this.data, targetData) && this.len === targetLen;
      if (this.match) {
        log(`[sub_16190 enter protected] data=${this.data} len=0x${this.len.toString(16)} key=${this.key} expected=${expected}`);
      }
    },
    onLeave(retval) {
      if (!this.match) return;
      const real = ptr(retval);
      retval.replace(expected);
      log(`[sub_16190 spoof protected] real=${real} -> ${expected}`);
      if (typeof onSpoof === 'function') {
        try { onSpoof(); } catch (e) { warn(`[sub_16190 spoof protected] onSpoof failed: ${e}`); }
      }
    }
  });

  sub16190FuncHookInstalled = true;
  log(`[hooked] sub_16190 function spoof @ ${addr} protected=${targetData}+0x${targetLen.toString(16)} expected=${expected}`);
}

function installCleanSub3E038DigestHook(loadBias) {
  if (!FORCE_CLEAN_SUB3E038_DIGEST) return;

  const digestBytes = runtimeCleanSub3E038DigestBytes || hexToBytes(CLEAN_SUB3E038_DIGEST_HEX);
  const digestSource = runtimeCleanSub3E038DigestBytes !== null ? 'runtime-clean' : 'static-fallback';
  const digestHex = hexBytes(digestBytes);
  const sub320b4 = loadBias.add(H_SUB_320B4_RVA);
  let forcedCount = 0;

  Interceptor.attach(sub320b4, {
    onEnter(args) {
      this.data = args[0];
      this.len = u64ToSafeNumber(args[1]);
      this.out = args[2];
      this.flag = args[3];

      // sub_3E038 hashes the hidden image header/range:
      //   sub_320B4(hidden_base, 0x7caa0, digest32, 0)
      // Only force this exact call, not every hash call in the protector.
      this.isSub3E038HiddenHash =
        this.len === CLEAN_SUB3E038_HASH_LEN &&
        ptrEq(this.data, loadBias);

      if (this.isSub3E038HiddenHash) {
        log(`[sub_320B4/sub_3E038 enter] data=${this.data} len=0x${this.len.toString(16)} out=${this.out} flag=${this.flag} caller=${moduleDesc(this.context.lr)}`);
      }
    },
    onLeave(retval) {
      if (!this.isSub3E038HiddenHash) return;

      const realDigest = readBytes(this.out, 32);
      const ok = tryWriteBytes(this.out, digestBytes);
      const forcedDigest = readBytes(this.out, 32);
      forcedCount++;

      log(`[sub_320B4/sub_3E038 force digest #${forcedCount}] real=${hexBytes(realDigest)} clean=${digestHex} source=${digestSource} ok=${ok} after=${hexBytes(forcedDigest)} ret=${retval}`);
    }
  });

  log(`[hooked] persistent clean sub_3E038 digest via sub_320B4 @ ${sub320b4} digest=${digestHex} source=${digestSource}`);
}


function installCrcTraceHooks(loadBias) {
  // Essential fix only: hidden code saves Frida/ART LR into qword_8CEF0; restore outer JNI_OnLoad return site.
  attachOnce(loadBias.add(CS_AFTER_STORE_QWORD_8CEF0), 'restore qword_8CEF0 outer return address', {
    onEnter() {
      if (outerHiddenReturnAddress === null) return;
      try {
        const slot = loadBias.add(H_QWORD_8CEF0_RVA);
        slot.writePointer(outerHiddenReturnAddress);
        this.context.sp.add(0x80).writePointer(outerHiddenReturnAddress);
      } catch (e) {
        warn(`[qword_8CEF0/saved LR fix] failed: ${e}`);
      }
    }
  });
}

function installClassesDatLoadSelectorSpoof(loadBias) {
  if (!FORCE_CLASSES_DAT_HASH_MATCH) return;
  const sub6a05c = loadBias.add(H_SUB_6A05C_RVA);
  attachOnce(sub6a05c, USE_CLEAN_COPY_FOR_CLASSES_SELECTOR_HASH
      ? 'sub_6A05C classes.dex.dat selector hash over clean snapshot'
      : 'sub_6A05C force classes.dex.dat selector hash match', {
    onEnter(args) {
      this.enabled = false;
      this.caller = moduleDesc(this.context.lr);
      const len = u64ToSafeNumber(args[1]);
      // sub_3EB6C does:
      //   v12 = sub_6A05C(hidden_base, 0x7caa0, 0)
      //   v13 = *(container_end - 0x20)
      //   if (v12 == v13) load /classes0../classes1 else load fallback /classes2
      this.enabled =
        this.caller.indexOf('hidden+0x3ec5c') === 0 &&
        ptrEq(args[0], loadBias) &&
        len === CLEAN_SUB3E038_HASH_LEN &&
        ptrEq(args[2], ptr(0));
      if (!this.enabled) return;

      this.containerEnd = this.context.x21;
      try { this.expected = this.containerEnd.add(-0x20).readPointer(); }
      catch (_) { this.expected = ptr(0); }
      this.originalData = args[0];
      this.cleanCopy = runtimeCleanHiddenImageCopy;
      if (USE_CLEAN_COPY_FOR_CLASSES_SELECTOR_HASH && this.cleanCopy !== null && !this.cleanCopy.isNull()) {
        args[0] = this.cleanCopy;
      }
      log(`[classes.dex.dat selector enter] caller=${this.caller} data=${this.originalData} len=0x${len.toString(16)} seed=${args[2]} container_end=${this.containerEnd} expected_v13=${this.expected} clean_copy=${this.cleanCopy}${USE_CLEAN_COPY_FOR_CLASSES_SELECTOR_HASH ? ' arg0->clean' : ''}`);
    },
    onLeave(retval) {
      if (!this.enabled) return;
      const real = ptr(retval);
      if (USE_CLEAN_COPY_FOR_CLASSES_SELECTOR_HASH) {
        const ok = ptrEq(real, this.expected);
        log(`[classes.dex.dat selector clean-copy] v12=${real} v13=${this.expected} match=${ok}; retval unchanged; expected field untouched`);
      } else {
        if (!this.expected.isNull()) retval.replace(this.expected);
        log(`[classes.dex.dat selector spoof] real_v12=${real} -> v13=${this.expected}; force v12==v13 so sub_3EB6C loads /classes0 and /classes1`);
      }
    }
  });
}

// [native-only] Removed installFinalGateTraceHooks Java/JNI diagnostic hook block.

function installDpMp3TraceHooks(loadBias) {
  const sub402e0 = loadBias.add(H_SUB_402E0_RVA);
  const sub20754 = loadBias.add(H_SUB_20754_RVA);
  const sub71844 = loadBias.add(H_SUB_71844_RVA);
  const sub6a05c = loadBias.add(H_SUB_6A05C_RVA);
  const sub4e340 = loadBias.add(H_SUB_4E340_RVA);
  const sub41108 = loadBias.add(H_SUB_41108_RVA);
  const sub4ddb4 = loadBias.add(H_SUB_4DDB4_RVA);
  const sub4e338 = loadBias.add(H_SUB_4E338_RVA);
  const sub54b10 = loadBias.add(H_SUB_54B10_RVA);
  const byte8cb48 = loadBias.add(H_BYTE_8CB48_RVA);
  const active = {};

  function isActiveTid(tid) { return active[tid] !== undefined; }
  function activeState(tid) { return active[tid]; }

  attachOnce(sub402e0, 'DPMP3 sub_402E0 dp.mp3 loader trace', {
    onEnter(args) {
      this.tid = this.threadId;
      this.caller = moduleDesc(this.context.lr);
      this.enabled = this.caller.indexOf('hidden+0x4f') === 0;
      if (!this.enabled) return;
      const st = {
        id: ++seq,
        env: args[0],
        v54: args[1],
        flag: args[2],
        outOrTmp: args[3],
        opened: null,
        decrypted: null,
        decompressed: null,
        hashReal: null,
        hashExpected: null,
      };
      active[this.tid] = st;
      let b = 0;
      try { b = byte8cb48.readU8(); } catch (_) {}
      log(`\n[DPMP3 enter #${st.id}] sub_402E0 caller=${this.caller} env=${args[0]} v54=${args[1]} flag=${args[2]} byte_8CB48_before=${b}`);
      try { log(`[DPMP3 v54 first32] ${hexBytes(readBytes(args[1], 32))}`); } catch (_) {}
    },
    onLeave(retval) {
      if (!this.enabled) return;
      const st = active[this.tid];
      let b = 0;
      try { b = byte8cb48.readU8(); } catch (_) {}
      log(`[DPMP3 leave #${st ? st.id : '?'}] ret=${retval} signed=${retval.toInt32()} byte_8CB48_after=${b}`);
      delete active[this.tid];
    }
  });

  // sub_54944(4, out3) happens before sub_402E0 active marker? It is inside sub_402E0, so trace by LR.
  attachOnce(loadBias.add(H_SUB_54944_RVA), 'DPMP3 sub_54944 open dp.mp3 asset', {
    onEnter(args) {
      this.tid = this.threadId;
      this.fromDp = isActiveTid(this.tid) && args[0].toInt32() === 4;
      if (!this.fromDp) return;
      this.out = args[1];
      log(`[DPMP3 open enter] sub_54944 id=${args[0]} out=${this.out}`);
    },
    onLeave(retval) {
      if (!this.fromDp) return;
      log(`[DPMP3 open leave] ret=${retval} signed=${retval.toInt32()}`);
      if (retval.toInt32() !== 0) return;
      try {
        const base = this.out.readPointer();
        const size = this.out.add(Process.pointerSize).readPointer().toUInt32();
        const handle = this.out.add(Process.pointerSize * 2).readPointer();
        log(`[DPMP3 asset] base=${base} size=0x${size.toString(16)} handle=${handle}`);
        dumpPreview('DPMP3 encrypted asset', base, Math.min(size, 0x80));
        try { dumpMemoryToFile('dp_mp3_raw_encrypted_asset.bin', base, size); } catch (e) { warn(`[DPMP3 dump raw failed] ${e}`); }
      } catch (e) { warn(`[DPMP3 open parse failed] ${e}`); }
    }
  });

  attachOnce(sub20754, 'DPMP3 sub_20754 decrypt dp.mp3', {
    onEnter(args) {
      this.tid = this.threadId;
      this.fromDp = isActiveTid(this.tid);
      if (!this.fromDp) return;
      this.len = u64ToSafeNumber(args[1]);
      this.nonce = args[2];
      this.tag = args[5];
      this.input = args[6];
      this.out = args[7];
      log(`[DPMP3 decrypt enter] len=0x${this.len.toString(16)} in=${this.input} tag=${this.tag} nonce=${this.nonce} out=${this.out}`);
    },
    onLeave(retval) {
      if (!this.fromDp) return;
      log(`[DPMP3 decrypt leave] ret=${retval.toInt32()} out=${this.out} len=0x${this.len.toString(16)}`);
      if (retval.toInt32() !== 0) return;
      try {
        const decompSize = this.out.readU32() >>> 0;
        const compSize = Math.max(0, this.len - 4);
        log(`[DPMP3 decrypted] decomp_size=0x${decompSize.toString(16)} comp_size=0x${compSize.toString(16)}`);
        dumpPreview('DPMP3 decrypted with size+compressed', this.out, Math.min(this.len, 0x100));
        try { dumpMemoryToFile('dp_mp3_decrypted_with_size_and_compressed.bin', this.out, this.len); } catch (e) { warn(`[DPMP3 dump decrypted failed] ${e}`); }
      } catch (e) { warn(`[DPMP3 decrypted parse failed] ${e}`); }
    }
  });

  attachOnce(sub71844, 'DPMP3 sub_71844 decompress dp.mp3', {
    onEnter(args) {
      this.tid = this.threadId;
      this.fromDp = isActiveTid(this.tid);
      if (!this.fromDp) return;
      this.out = args[0];
      this.expected = u64ToSafeNumber(args[1]);
      this.comp = args[2];
      this.compLen = u64ToSafeNumber(args[3]);
      const st = activeState(this.tid);
      if (st) st.decompOut = this.out;
      log(`[DPMP3 decompress enter] out=${this.out} expected=0x${this.expected.toString(16)} comp=${this.comp} comp_len=0x${this.compLen.toString(16)}`);
    },
    onLeave(retval) {
      if (!this.fromDp) return;
      const written = u64ToSafeNumber(retval);
      log(`[DPMP3 decompress leave] written=0x${written.toString(16)} expected=0x${this.expected.toString(16)}`);
      const len = Math.min(written, this.expected);
      if (len <= 0) return;
      try {
        dumpPreview('DPMP3 decompressed', this.out, Math.min(len, 0x100));
        const firstQ = this.out.readPointer();
        const u32_20 = this.out.add(0x20).readU32() >>> 0;
        const u32_24 = this.out.add(0x24).readU32() >>> 0;
        log(`[DPMP3 decompressed header] first_qword=${firstQ} u32_20=${u32_20} u32_24=${u32_24}`);
        try { dumpMemoryToFile('dp_mp3_decompressed.bin', this.out, len); } catch (e) { warn(`[DPMP3 dump decompressed failed] ${e}`); }
      } catch (e) { warn(`[DPMP3 decompressed parse failed] ${e}`); }
    }
  });

  attachOnce(sub6a05c, 'DPMP3 sub_6A05C hash compare inside sub_402E0', {
    onEnter(args) {
      this.tid = this.threadId;
      this.fromDp = isActiveTid(this.tid) && moduleDesc(this.context.lr).indexOf('hidden+0x404') === 0;
      if (!this.fromDp) return;
      this.data = args[0];
      this.len = u64ToSafeNumber(args[1]);
      this.seed = args[2];
      const st = activeState(this.tid);
      this.decomp = st && st.decompOut ? st.decompOut : ptr(0);
      try { this.expected = this.decomp.readPointer(); } catch (_) { this.expected = ptr(0); }
      this.cleanCopy = runtimeCleanHiddenImageCopy;
      if (this.cleanCopy !== null && !this.cleanCopy.isNull() && ptrEq(this.data, loadBias) && this.len === CLEAN_SUB3E038_HASH_LEN) {
        args[0] = this.cleanCopy;
        log(`[DPMP3 hash clean-copy] caller=${moduleDesc(this.context.lr)} arg0 ${this.data} -> ${this.cleanCopy}`);
      }
      log(`[DPMP3 hash enter] caller=${moduleDesc(this.context.lr)} data=${this.data} len=0x${this.len.toString(16)} seed=${this.seed} decomp=${this.decomp} expected_first_qword=${this.expected}`);
    },
    onLeave(retval) {
      if (!this.fromDp) return;
      const real = ptr(retval);
      const ok = ptrEq(real, this.expected);
      let b = 0;
      try { b = byte8cb48.readU8(); } catch (_) {}
      log(`[DPMP3 hash leave] real=${real} expected_first_qword=${this.expected} match=${ok} byte_8CB48_now=${b}`);
    }
  });

  function traceInstaller(addr, name) {
    attachOnce(addr, `DPMP3 ${name}`, {
      onEnter(args) {
        this.tid = this.threadId;
        this.fromDp = isActiveTid(this.tid);
        if (!this.fromDp) return;
        this.caller = moduleDesc(this.context.lr);
        log(`[DPMP3 ${name} enter] caller=${this.caller} x0=${args[0]} x1=${args[1]} x2=${args[2]} x3=${args[3]} x4=${args[4]} x5=${args[5]}`);
      },
      onLeave(retval) {
        if (!this.fromDp) return;
        let signed = '<err>';
        try { signed = retval.toInt32(); } catch (_) {}
        log(`[DPMP3 ${name} leave] ret=${retval} signed=${signed}`);
      }
    });
  }
  // installer helper traces removed: not required for bypass.
}


function installSub55718IntegrityBypass(loadBias) {
  if (!BYPASS_SUB55718_INTEGRITY_COMPARE) {
    log('[skip] sub_55718 clean-snapshot HMAC bypass disabled');
    return;
  }

  const sub15f44 = loadBias.add(H_SUB_15F44_RVA);
  const callerSub55718CleanHash = loadBias.add(ptr('0x55950')); // return address after sub_15F44(empty, hidden_base, 0x7caa0, v45)
  attachOnce(sub15f44, 'sub_55718 HMAC hidden_base -> clean snapshot', {
    onEnter(args) {
      this.enabled = false;
      this.caller = this.context.lr;
      const keyLen = u64ToSafeNumber(args[1]);
      const data = args[2];
      const len = u64ToSafeNumber(args[3]);

      this.enabled =
        ptrEq(this.caller, callerSub55718CleanHash) &&
        keyLen === 0 &&
        ptrEq(data, loadBias) &&
        len === CLEAN_SUB3E038_HASH_LEN &&
        runtimeCleanHiddenImageCopy !== null &&
        !runtimeCleanHiddenImageCopy.isNull();

      if (!this.enabled) return;

      this.origData = data;
      this.cleanData = runtimeCleanHiddenImageCopy;
      this.out = args[4];
      this.expected = this.context.x20; // in sub_55718 this is asset+0x20, the expected 32-byte HMAC
      this.expectedHex = hexBytes(readBytes(this.expected, 32));
      args[2] = this.cleanData;
      log(`[sub_55718 HMAC redirect] caller=${moduleDesc(this.caller)} key_len=0 data ${this.origData}->${this.cleanData} len=0x${len.toString(16)} out=${this.out} expected=${this.expectedHex}`);
    },
    onLeave(retval) {
      if (!this.enabled) return;
      const digest = readBytes(this.out, 32);
      const expected = readBytes(this.expected, 32);
      log(`[sub_55718 HMAC leave] digest=${hexBytes(digest)} expected=${hexBytes(expected)} match=${bytesEq(digest, expected)} ret=${retval}`);
    }
  });
}

function installHiddenHooks(loadBias) {
  const key = loadBias.toString();
  if (installedHiddenBases.has(key)) return;
  installedHiddenBases.add(key);
  hiddenBase = loadBias;
  mkdirOne(DUMP_DIR);

  const sub4e354 = loadBias.add(H_SUB_4E354_RVA);
  const sub4e7d8 = loadBias.add(H_SUB_4E7D8_RVA);
  const sub5e684 = loadBias.add(H_SUB_5E684_RVA);
  const sub54944 = loadBias.add(H_SUB_54944_RVA);
  const sub20754 = loadBias.add(H_SUB_20754_RVA);
  const sub71844 = loadBias.add(H_SUB_71844_RVA);
  const expectedHashAddr = loadBias.add(H_QWORD_8CEF8_RVA);

  log(`[hidden] load_bias=${loadBias}`);
  log(`[bypass] qword_8CEF8 @ ${expectedHashAddr} = ${readU64Ptr(expectedHashAddr)}`);
  installWatchdogThreadBlocker(loadBias);
  installCleanSub3E038DigestHook(loadBias);
  installSub16190FunctionSpoof(loadBias);
  installCrcTraceHooks(loadBias);
  // [native-only] Java/JNI final gate trace hooks removed.
  log('[skip] final gate/JNI trace removed for native-only test');
  installClassesDatLoadSelectorSpoof(loadBias);
  installDpMp3TraceHooks(loadBias);
  installSub55718IntegrityBypass(loadBias);

  function logSub4E7D8Enter(code, raw, caller) {
    // From sub_4E7D8 pseudocode:
    //   code == 0  : normal finalizer path, then RegisterNatives(... ye()V -> sub_4F9DC)
    //   code != 0  : error/report path; may build/report MessageGuardException
    // Do not label code=0 as an error.
    if (code === 0) {
      log(`\n[sub_4E7D8 enter] code=0 raw=${raw} caller=${caller} path=success_finalizer_register_ye`);
    } else {
      log(`\n[sub_4E7D8 enter] code=${code} raw=${raw} caller=${caller} path=error_report_messageguard`);
    }
  }

  attachOnce(sub4e354, 'sub_4E354 hidden native entry', {
    onEnter(args) {
      this.id = ++seq;
      log(`\n[sub_4E354/ProtectedApplication.ye enter #${this.id}] x0=${args[0]} caller=${moduleDesc(this.context.lr)}`);
    },
    onLeave(retval) {
      log(`[sub_4E354/ProtectedApplication.ye leave #${this.id}] ret=${retval}`);
    }
  });

  if (NOOP_SUB4E7D8_CODE0) {
    const k = `wrap:sub_4E7D8@${sub4e7d8}`;
    if (!hooked.has(k)) {
      let origSub4e7d8 = null;
      const wrapper = new NativeCallback(function (env, code) {
        const n = code | 0;
        if (n === 0) {
          log(`\n[sub_4E7D8 noop] code=0 path=success_finalizer_register_ye env=${env} -> return`);
          return;
        }
        log(`\n[sub_4E7D8 enter] code=${n} env=${env} path=error_report_messageguard`);
        if (origSub4e7d8 !== null) origSub4e7d8(env, n);
      }, 'void', ['pointer', 'int']);

      try {
        if (typeof Interceptor.replaceFast === 'function') {
          const origPtr = Interceptor.replaceFast(sub4e7d8, wrapper);
          origSub4e7d8 = new NativeFunction(origPtr, 'void', ['pointer', 'int']);
          log(`[replaced-fast] sub_4E7D8 code0 no-op wrapper @ ${sub4e7d8} orig=${origPtr}`);
        } else {
          origSub4e7d8 = new NativeFunction(sub4e7d8, 'void', ['pointer', 'int']);
          Interceptor.replace(sub4e7d8, wrapper);
          log(`[replaced] sub_4E7D8 code0 no-op wrapper @ ${sub4e7d8}`);
        }
        hooked.add(k);
      } catch (e) {
        warn(`[replace FAIL] sub_4E7D8 wrapper @ ${sub4e7d8}: ${e}; falling back to attach-only log`);
        attachOnce(sub4e7d8, 'sub_4E7D8 enter', {
          onEnter(args) {
            let code = -1;
            try { code = args[1].toInt32(); } catch (_) {}
            logSub4E7D8Enter(code, args[1], moduleDesc(this.context.lr));
          }
        });
      }
    }
  } else {
    attachOnce(sub4e7d8, 'sub_4E7D8 enter', {
      onEnter(args) {
        let code = -1;
        try { code = args[1].toInt32(); } catch (_) {}
        logSub4E7D8Enter(code, args[1], moduleDesc(this.context.lr));
      }
    });
  }

  // IMPORTANT:
  // sub_3E038 derives the later ic.dat key by scanning 16K pages from around 0x3e064 downward.
  // If we hook low helper functions early (sub_16190 @0x16190, sub_15DD4 @0x15DD4,
  // sub_20754 @0x20754, sub_363F0/3601C/3662C...), Frida patches those pages and the key becomes wrong.
  // So: hook safe call-sites in sub_4E354 page instead, and delay low-page hooks until after sub_3E038.

  function hookCallsiteForceZero(rva, name, alsoZeroX20) {
    attachOnce(loadBias.add(rva), `callsite ${name} -> zero`, {
      onEnter() {
        const beforeX0 = this.context.x0;
        const beforeW20 = this.context.x20;
        if (beforeX0.toInt32() !== 0 || (alsoZeroX20 && beforeW20.toInt32() !== 0)) {
          log(`[callsite BYPASS] ${name} before x0=${beforeX0} x20=${beforeW20} caller=${moduleDesc(this.context.lr)}`);
        }
        this.context.x0 = ptr(0);
        if (alsoZeroX20) this.context.x20 = ptr(0);
      }
    });
  }

  function hookFunctionReturnZero(rva, name) {
    attachOnce(loadBias.add(rva), `function ${name} -> zero`, {
      onEnter() {
        this.lr = this.context.lr;
      },
      onLeave(retval) {
        const before = retval.toInt32();
        if (before !== 0) {
          log(`[function BYPASS] ${name} ret=${before} raw=${retval} caller=${moduleDesc(this.lr)} -> 0`);
        }
        retval.replace(0);
      }
    });
  }

  // Low-page checks are bypassed from their return sites, not by hooking the low helper functions.
  hookCallsiteForceZero(CS_AFTER_SUB3B6D8, 'after sub_3B6D8', false);
  hookCallsiteForceZero(CS_AFTER_SUB363F0, 'after sub_363F0/sdk_check', false);
  hookCallsiteForceZero(CS_AFTER_SUB5CB1C, 'after sub_5CB1C/watchdog_spawn_1', false);
  hookCallsiteForceZero(CS_AFTER_SUB5D6F0, 'after sub_5D6F0/watchdog_spawn_2', true);
  if (BYPASS_SUB3601C_3662C_BY_FUNCTION) {
    log('[callsite SKIP] not hooking hidden+0x4e514/0x4e524; bypass sub_3601C/sub_3662C at function return instead');
    hookFunctionReturnZero(H_SUB_3601C_RVA, 'sub_3601C');
    hookFunctionReturnZero(H_SUB_3662C_RVA, 'sub_3662C');
  } else {
    hookCallsiteForceZero(CS_AFTER_SUB3601C, 'after sub_3601C', false);
    hookCallsiteForceZero(CS_AFTER_SUB3662C, 'after sub_3662C', false);
  }
  hookCallsiteForceZero(CS_AFTER_SUB36764, 'after sub_36764', false);

  // Above-scan-range checks are safe to hook/replace directly.
  const preChecks = [
    // Essential: sub_5C4A4 detects Frida in maps and can poison later checks.
    // It is above the self-key scan range, so replacing it does not disturb sub_3E038.
    ['sub_5C4A4_maps_libc_art_check', 0x5c4a4, 'replace'],
  ];

  preChecks.forEach(([name, off, mode]) => {
    const addr = loadBias.add(ptr(off));
    if (mode === 'replace' && BYPASS_PRE_ICDAT_CHECKS) {
      let n = 0;
      replaceOnce(addr, `precheck ${name} -> 0`, new NativeCallback(function () {
        n++;
        // Normal successful sub_5C4A4 ends by clearing byte_8A0D4. Keep that side effect.
        try { loadBias.add(ptr('0x8a0d4')).writeU8(0); } catch (_) {}
        // Keep qword_8CEF0 pointing into the outer libdexprotector.so. sub_5F0D0 later uses it
        // to recover the APK path; if it points to a Frida/ART trampoline it returns 731.
        try {
          if (outerHiddenReturnAddress !== null) {
            loadBias.add(H_QWORD_8CEF0_RVA).writePointer(outerHiddenReturnAddress);
          }
        } catch (_) {}
        log(`[precheck SKIP] ${name} call#${n} ret -> 0; byte_8A0D4=0 qword_8CEF0=${outerHiddenReturnAddress}`);
        return 0;
      }, 'int', []));
      return;
    }

    attachOnce(addr, `precheck ${name}`, {
      onEnter() { this.lr = this.context.lr; },
      onLeave(retval) {
        const code = retval.toInt32();
        if (code !== 0) {
          log(`[precheck FAIL] ${name} ret=${code} raw=${retval} caller=${moduleDesc(this.lr)}`);
          if (BYPASS_PRE_ICDAT_CHECKS) {
            retval.replace(0);
            log(`[precheck BYPASS] ${name} ret -> 0`);
          }
        }
      }
    });
  });

  if (BYPASS_SUB16190_COMPARE) {
    // Code integrity compare site after BL sub_16190.
    attachOnce(loadBias.add(CS_AFTER_SUB16190), 'callsite after sub_16190 compare spoof', {
      onEnter() {
        const expected = this.context.x20;
        const real = this.context.x0;
        const ctx = this.context.sp.add(0x20);
        log(`[callsite sub_16190] real=${real} expected(x20)=${expected} ctx64=${hexBytes(readBytes(ctx, 64))}; installing delayed ic.dat hook`);
        this.context.x0 = expected; // CMP X20, X0 will pass.
        installDelayedIcDecryptHook();
      }
    });

    // Belt-and-suspenders: if branch still reaches the tamper/poison path, jump over sub_15E24.
    attachOnce(loadBias.add(CS_POISON_PATH), 'callsite poison path guard', {
      onEnter() {
        log('[POISON PATH HIT] skipping sub_15E24 tamper update -> loc_4E608');
        this.context.pc = loadBias.add(ptr('0x4e608'));
      }
    });
  } else {
    log('[option3] sub_16190 compare bypass disabled; poison guard disabled');
  }

  // Magic compare site after BL sub_15DD4. Do not hook sub_15DD4 itself before sub_3E038.
  // Only log the real output here; do not spoof. This tells us whether current v54 is already correct.
  attachOnce(loadBias.add(CS_AFTER_SUB15DD4), 'callsite after sub_15DD4 log actual output', {
    onEnter() {
      const out = this.context.sp.add(0x14); // var_9C in sub_4E354 frame
      const keyCtx = this.context.sp.add(0x20); // var_90/v54 in sub_4E354 frame
      const input = this.context.sp.add(0x18);  // var_98 = 0x91A4FB076B659459
      const actual = readBytes(out, 4);         // real sub_15DD4 output before our spoof
      const v54 = readBytes(keyCtx, 32);
      const input8 = readBytes(input, 8);
      const expected = readBytes(loadBias.add(ptr('0x8976c')), 4) || EXPECTED_MAGIC_4E354;
      const actualMatchesExpected = bytesEq(actual, expected);

      log(`[sub_15DD4 actual] v54=${hexBytes(v54)} input=${hexBytes(input8)} out=${hexBytes(actual)} expected=${hexBytes(expected)} v54_ok=${actualMatchesExpected}`);
      installDelayedIcDecryptHook();
    }
  });

  // Install only after sub_16190 has already computed code hash. sub_20754 lives inside 0x10e00..0x771e8,
  // so installing it before sub_16190 can change the hash input.
  let delayedIcDecryptHookInstalled = false;
  function installDelayedIcDecryptHook() {
    if (delayedIcDecryptHookInstalled) return;
    delayedIcDecryptHookInstalled = true;
    attachOnce(sub20754, 'sub_20754 decrypt ic.dat DELAYED', {
      onEnter(args) {
        this.fromIc = ptrEq(this.context.lr, loadBias.add(RA_AFTER_DECRYPT));
        if (!this.fromIc) return;
        this.len = args[1].toUInt32();        // ciphertext len = asset_size - 16
        this.nonce = args[2];
        this.tag = args[5];
        this.input = args[6];
        this.out = args[7];
        log(`[ic.dat decrypt enter] len=0x${this.len.toString(16)} in=${this.input} tag=${this.tag} nonce=${this.nonce} out=${this.out}`);
      },
      onLeave(retval) {
        if (!this.fromIc) return;
        const ret = retval.toInt32();
        log(`[ic.dat decrypt leave] ret=${ret} out=${this.out} len=0x${this.len.toString(16)}`);
        if (ret !== 0) return;
        try {
          const decompSize = this.out.readU32();
          const compSize = this.len >= 4 ? this.len - 4 : 0;
          log(`[ic.dat decrypted] decomp_size=0x${decompSize.toString(16)} comp_size=0x${compSize.toString(16)}`);
          dumpPreview('ic.dat decrypted', this.out, this.len);
          dumpMemoryToFile('ic_decrypted_with_size_and_compressed.bin', this.out, this.len);
          if (compSize > 0) dumpMemoryToFile('ic_decrypted_compressed_payload.bin', this.out.add(4), compSize);
        } catch (e) { warn(`[ic.dat decrypted] dump failed: ${e}`); }
      }
    });
  }

  // Do not hook CS_AFTER_SUB3E038. It sits right before sub_16190 setup; keeping it clean avoids
  // relocation/trampoline weirdness and avoids touching low-page code before integrity hash.

  if (WRAP_SUB5E684_WITH_ORIGINAL) {
    const k = `wrap:sub_5E684@${sub5e684}`;
    if (!hooked.has(k)) {
      let origSub5e684 = null;
      const wrapper = new NativeCallback(function (ctx) {
        const id = ++seq;
        if (SKIP_SUB5E684_AFTER_FIRST_SUCCESS && sub5e684HadSuccess) {
          log(`\n[sub_5E684 wrapper skip #${id}] duplicate after first success ctx=${ctx} -> ret 0`);
          return 0;
        }

        log(`\n[sub_5E684 wrapper enter #${id}] ctx=${ctx}`);
        const ret = origSub5e684(ctx);
        log(`[sub_5E684 wrapper leave #${id}] ret=${ret}`);
        if (ret === 0) sub5e684HadSuccess = true;
        return ret;
      }, 'int', ['pointer']);

      try {
        if (typeof Interceptor.replaceFast === 'function') {
          const origPtr = Interceptor.replaceFast(sub5e684, wrapper);
          origSub5e684 = new NativeFunction(origPtr, 'int', ['pointer']);
          log(`[replaced-fast] sub_5E684 wrapper first-run then skip duplicates @ ${sub5e684} orig=${origPtr}`);
        } else {
          origSub5e684 = new NativeFunction(sub5e684, 'int', ['pointer']);
          Interceptor.replace(sub5e684, wrapper);
          log(`[replaced] sub_5E684 wrapper first-run then skip duplicates @ ${sub5e684}`);
        }
        hooked.add(k);
      } catch (e) {
        warn(`[replace FAIL] sub_5E684 wrapper @ ${sub5e684}: ${e}; falling back to attach-only log`);
      }
    }
  } else {
    attachOnce(sub5e684, 'sub_5E684 ic.dat integrity check', {
      onEnter(args) {
        this.id = ++seq;
        this.ctx = args[0];
        log(`\n[sub_5E684 enter #${this.id}] ctx=${this.ctx} caller=${moduleDesc(this.context.lr)}`);
      },
      onLeave(retval) {
        log(`[sub_5E684 leave #${this.id}] ret=${retval} (${retval.toInt32 ? retval.toInt32() : retval})`);
        try {
          if (retval.toInt32() === 0) sub5e684HadSuccess = true;
        } catch (_) {}
      }
    });
  }

  // Optional raw encrypted asset dump: sub_54944(6, out3) from sub_5E684.
  attachOnce(sub54944, 'sub_54944 open asset', {
    onEnter(args) {
      this.id = args[0].toInt32();
      this.out = args[1];
      this.fromIc = ptrEq(this.context.lr, loadBias.add(RA_AFTER_OPEN_ICDAT));
    },
    onLeave(retval) {
      if (!this.fromIc || this.id !== 6) return;
      const ret = retval.toInt32();
      log(`[ic.dat raw open] ret=${ret} out=${this.out}`);
      if (ret !== 0) return;
      try {
        const base = this.out.readPointer();
        const sizePtr = this.out.add(Process.pointerSize).readPointer();
        const size = sizePtr.toUInt32();
        log(`[ic.dat raw] base=${base} size=0x${size.toString(16)} handle=${this.out.add(Process.pointerSize * 2).readPointer()}`);
        dumpPreview('ic.dat raw', base, size);
        dumpMemoryToFile('ic_raw_encrypted_asset.bin', base, size);
      } catch (e) { warn(`[ic.dat raw] dump failed: ${e}`); }
    }
  });

  // Dump fully decompressed ic.dat manifest.
  attachOnce(sub71844, 'sub_71844 decompress ic.dat', {
    onEnter(args) {
      this.fromIc = ptrEq(this.context.lr, loadBias.add(RA_AFTER_DECOMP));
      if (!this.fromIc) return;
      this.out = args[0];
      this.expected = args[1].toUInt32();
      this.comp = args[2];
      this.compLen = args[3].toUInt32();
      log(`[ic.dat decompress enter] out=${this.out} expected=0x${this.expected.toString(16)} comp=${this.comp} comp_len=0x${this.compLen.toString(16)}`);
    },
    onLeave(retval) {
      if (!this.fromIc) return;
      const written = retval.toUInt32();
      log(`[ic.dat decompress leave] written=0x${written.toString(16)} expected=0x${this.expected.toString(16)}`);
      const len = Math.min(written, this.expected);
      if (len <= 0) return;
      try {
        dumpPreview('ic.dat decompressed', this.out, len);
        dumpMemoryToFile('ic_decompressed.bin', this.out, len);

        if (len >= 0x24) {
          const key0 = readBytes(this.out, 16);
          const expectedHash = this.out.add(0x18).readU64();
          const count = this.out.add(0x20).readU32();
          log(`[ic.dat parsed] siphash_key16=${hexBytes(key0)} expected_hash=${expectedHash} entry_count=${count}`);
          try {
            const names = this.out.add(0x24).readCString(Math.min(len - 0x24, 4096));
            log(`[ic.dat first names] ${JSON.stringify(names.slice(0, 300))}`);
          } catch (_) {}
        }
      } catch (e) { warn(`[ic.dat decompressed] dump failed: ${e}`); }
    }
  });
}


// -----------------------------------------------------------------------------
// LibApplication.i resolver tracer
// -----------------------------------------------------------------------------
const LIBAPP_CLASS = 'com.dexprotector.detector.envchecks.LibApplication';
// Keep JNI resolver off by default: hooking JNIEnv Get*ID/FindClass is useful but can be noisy/fragile.
const TRACE_LIBAPP_REFLECTION_RESOLVER = false; // enable only when Java reflection-level resolution is needed
const TRACE_LIBAPP_JNI_RESOLVER = false;        // enable only for short targeted runs; JNIEnv hooks are fragile/noisy
const TRACE_LIBAPP_JAVA_STACK = false;          // stack capture inside dispatcher can perturb protected code
const TRACE_LIBAPP_OBJECT_TOSTRING = false;     // avoid toString() side effects during class init
// Optional: set to [9320] (or any signed opcode) to focus nested resolver logs on one dispatch chain.
const TRACE_LIBAPP_FOCUS_OPCODES = [];
const TRACE_LIBAPP_LOG_ALL_CALLS = true;        // if false, only logs focus opcode chains
const libAppTrace = {
  installed: false,
  installing: false,
  reflectInstalled: false,
  jniInstalled: false,
  seq: 0,
  depthByTid: {},
  resolveDepthByTid: {},
  methodIds: {},
  fieldIds: {},
};

function libAppDepth(tid) {
  tid = tid || Process.getCurrentThreadId();
  return libAppTrace.depthByTid[tid] || 0;
}

function libAppEnterDepth(tid) {
  libAppTrace.depthByTid[tid] = libAppDepth(tid) + 1;
}

function libAppLeaveDepth(tid) {
  const d = libAppDepth(tid) - 1;
  if (d <= 0) delete libAppTrace.depthByTid[tid];
  else libAppTrace.depthByTid[tid] = d;
}

function libAppResolveDepth(tid) {
  tid = tid || Process.getCurrentThreadId();
  return libAppTrace.resolveDepthByTid[tid] || 0;
}

function libAppEnterResolve(tid) {
  libAppTrace.resolveDepthByTid[tid] = libAppResolveDepth(tid) + 1;
}

function libAppLeaveResolve(tid) {
  const d = libAppResolveDepth(tid) - 1;
  if (d <= 0) delete libAppTrace.resolveDepthByTid[tid];
  else libAppTrace.resolveDepthByTid[tid] = d;
}

function tryOpcodeNumber(argsLike) {
  if (!argsLike || argsLike.length === 0) return null;
  const a0 = argsLike[0];
  if (typeof a0 === 'number') return a0 | 0;
  try {
    if (a0 && typeof a0.intValue === 'function') return a0.intValue() | 0;
  } catch (_) {}
  return null;
}

function opcodeIsFocused(op) {
  if (TRACE_LIBAPP_FOCUS_OPCODES.length === 0 || op === null) return false;
  const u = op >>> 0;
  return TRACE_LIBAPP_FOCUS_OPCODES.some(x => ((x | 0) === op) || ((x >>> 0) === u));
}

function safeJavaClassName(obj) {
  if (obj === null || obj === undefined) return String(obj);
  try {
    const JObject = Java.use('java.lang.Object');
    return Java.cast(obj, JObject).getClass().getName().toString();
  } catch (e) {
    try { return obj.$className || String(obj); } catch (_) { return '<java-class?>'; }
  }
}

function previewJavaArray(arr, maxItems) {
  if (arr === null || arr === undefined) return String(arr);
  maxItems = maxItems || 8;
  try {
    const JArray = Java.use('java.lang.reflect.Array');
    const n = JArray.getLength(arr);
    const out = [];
    const m = Math.min(n, maxItems);
    for (let i = 0; i < m; i++) {
      let v = null;
      try { v = JArray.get(arr, i); } catch (e) { out.push(`<${i}: ${e}>`); continue; }
      out.push(describeJavaValue(v, 1));
    }
    if (n > m) out.push(`... +${n - m}`);
    return `[len=${n} ${out.join(', ')}]`;
  } catch (e) {
    try { return arr.toString(); } catch (_) { return `<array-preview-failed: ${e}>`; }
  }
}

function describeJavaValue(v, depth) {
  depth = depth || 0;
  if (v === null || v === undefined) return String(v);
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (typeof v === 'string') return JSON.stringify(v);

  let cls = '<unknown>';
  try { cls = safeJavaClassName(v); } catch (_) {}

  if (cls[0] === '[') {
    return `${cls}${previewJavaArray(v, depth > 0 ? 5 : 10)}`;
  }

  if (!TRACE_LIBAPP_OBJECT_TOSTRING) return cls;
  let s = '';
  try { s = v.toString(); } catch (_) { s = '<toString failed>'; }
  if (s && s.length > 220) s = s.slice(0, 220) + '...';
  return `${cls}:${JSON.stringify(String(s))}`;
}

function libAppArgsSummary(argsLike) {
  const out = [];
  for (let i = 0; i < argsLike.length; i++) out.push(`a${i}=${describeJavaValue(argsLike[i])}`);
  return out.join(' | ');
}

function tryExtractOpcode(argsLike) {
  if (!argsLike || argsLike.length === 0) return '<none>';
  const a0 = argsLike[0];
  if (typeof a0 === 'number') return `0x${(a0 >>> 0).toString(16)} (${a0})`;
  try {
    if (a0 && typeof a0.intValue === 'function') {
      const v = a0.intValue();
      return `0x${(v >>> 0).toString(16)} (${v})`;
    }
  } catch (_) {}
  return describeJavaValue(a0);
}

function javaStackShort() {
  try {
    const Exception = Java.use('java.lang.Exception');
    const st = Exception.$new().getStackTrace();
    const lines = [];
    const n = Math.min(st.length, 10);
    for (let i = 2; i < n; i++) lines.push('    at ' + st[i].toString());
    return lines.join('\n');
  } catch (e) {
    return `<stack failed: ${e}>`;
  }
}

function installReflectionResolverHooks() {
  if (libAppTrace.reflectInstalled) return;
  libAppTrace.reflectInstalled = true;
  try {
    const JClass = Java.use('java.lang.Class');
    const Method = Java.use('java.lang.reflect.Method');
    const Field = Java.use('java.lang.reflect.Field');

    function shouldLog() { return libAppResolveDepth() > 0; }

    const forName1 = JClass.forName.overload('java.lang.String');
    forName1.implementation = function (name) {
      if (shouldLog()) log(`[Reflect resolver] Class.forName(${JSON.stringify(String(name))})`);
      return forName1.call(this, name);
    };
    const forName3 = JClass.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');
    forName3.implementation = function (name, init, loader) {
      if (shouldLog()) log(`[Reflect resolver] Class.forName(${JSON.stringify(String(name))}, init=${init}, loader=${describeJavaValue(loader)})`);
      return forName3.call(this, name, init, loader);
    };

    const getDeclaredMethod = JClass.getDeclaredMethod.overload('java.lang.String', '[Ljava.lang.Class;');
    getDeclaredMethod.implementation = function (name, params) {
      if (shouldLog()) log(`[Reflect resolver] ${this.getName()}.getDeclaredMethod(${JSON.stringify(String(name))}, ${previewJavaArray(params, 8)})`);
      return getDeclaredMethod.call(this, name, params);
    };
    const getMethod = JClass.getMethod.overload('java.lang.String', '[Ljava.lang.Class;');
    getMethod.implementation = function (name, params) {
      if (shouldLog()) log(`[Reflect resolver] ${this.getName()}.getMethod(${JSON.stringify(String(name))}, ${previewJavaArray(params, 8)})`);
      return getMethod.call(this, name, params);
    };
    const getDeclaredField = JClass.getDeclaredField.overload('java.lang.String');
    getDeclaredField.implementation = function (name) {
      if (shouldLog()) log(`[Reflect resolver] ${this.getName()}.getDeclaredField(${JSON.stringify(String(name))})`);
      return getDeclaredField.call(this, name);
    };

    const methodInvoke = Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;');
    methodInvoke.implementation = function (receiver, argv) {
      if (shouldLog()) {
        let m = '<method>';
        try { m = `${this.getDeclaringClass().getName()}.${this.getName()}${this.toGenericString()}`; } catch (_) { try { m = this.toString(); } catch (_) {} }
        log(`[Reflect resolver] Method.invoke ${m} receiver=${describeJavaValue(receiver)} args=${previewJavaArray(argv, 8)}`);
      }
      return methodInvoke.call(this, receiver, argv);
    };

    const fieldGet = Field.get.overload('java.lang.Object');
    fieldGet.implementation = function (receiver) {
      if (shouldLog()) {
        let f = '<field>';
        try { f = `${this.getDeclaringClass().getName()}.${this.getName()}`; } catch (_) {}
        log(`[Reflect resolver] Field.get ${f} receiver=${describeJavaValue(receiver)}`);
      }
      return fieldGet.call(this, receiver);
    };

    log('[LibApp resolver] reflection resolver hooks installed');
  } catch (e) {
    warn(`[LibApp resolver] reflection hook install failed: ${e}`);
  }
}

function jniCString(p) {
  try { return safeCString(p); } catch (_) { return null; }
}

function installJniResolverHooksFromCurrentEnv() {
  if (libAppTrace.jniInstalled) return;
  try {
    const env = Java.vm.getEnv().handle;
    if (!env || env.isNull()) return;
    libAppTrace.jniInstalled = true;

    function shouldLogNative() { return libAppResolveDepth(Process.getCurrentThreadId()) > 0; }
    function hookJni(off, name, cb) {
      const fn = getJniFn(env, off);
      attachOnce(fn, `LibApp resolver JNI ${name}`, cb(fn));
    }

    hookJni(JNI_FIND_CLASS_OFF, 'FindClass', () => ({
      onEnter(args) { if (!shouldLogNative()) return; this.on = true; this.name = jniCString(args[1]); log(`[JNI resolver] FindClass ${JSON.stringify(this.name)}`); },
      onLeave(retval) { if (this.on) log(`[JNI resolver] FindClass -> ${retval} class=${JSON.stringify(this.name)}`); }
    }));

    hookJni(JNI_GET_METHOD_ID_OFF, 'GetMethodID', () => ({
      onEnter(args) { if (!shouldLogNative()) return; this.on = true; this.clazz = args[1]; this.name = jniCString(args[2]); this.sig = jniCString(args[3]); this.clsName = tryGetJClassName(args[0], this.clazz); log(`[JNI resolver] GetMethodID class=${JSON.stringify(this.clsName)} name=${JSON.stringify(this.name)} sig=${JSON.stringify(this.sig)}`); },
      onLeave(retval) { if (!this.on) return; libAppTrace.methodIds[retval.toString()] = `${this.clsName}.${this.name}${this.sig}`; log(`[JNI resolver] GetMethodID -> ${retval} ${libAppTrace.methodIds[retval.toString()]}`); }
    }));

    hookJni(JNI_GET_STATIC_METHOD_ID_OFF, 'GetStaticMethodID', () => ({
      onEnter(args) { if (!shouldLogNative()) return; this.on = true; this.clazz = args[1]; this.name = jniCString(args[2]); this.sig = jniCString(args[3]); this.clsName = tryGetJClassName(args[0], this.clazz); log(`[JNI resolver] GetStaticMethodID class=${JSON.stringify(this.clsName)} name=${JSON.stringify(this.name)} sig=${JSON.stringify(this.sig)}`); },
      onLeave(retval) { if (!this.on) return; libAppTrace.methodIds[retval.toString()] = `${this.clsName}.${this.name}${this.sig} [static]`; log(`[JNI resolver] GetStaticMethodID -> ${retval} ${libAppTrace.methodIds[retval.toString()]}`); }
    }));

    const JNI_GET_FIELD_ID_OFF_LOCAL = 0x2f0;
    hookJni(JNI_GET_FIELD_ID_OFF_LOCAL, 'GetFieldID', () => ({
      onEnter(args) { if (!shouldLogNative()) return; this.on = true; this.clazz = args[1]; this.name = jniCString(args[2]); this.sig = jniCString(args[3]); this.clsName = tryGetJClassName(args[0], this.clazz); log(`[JNI resolver] GetFieldID class=${JSON.stringify(this.clsName)} name=${JSON.stringify(this.name)} sig=${JSON.stringify(this.sig)}`); },
      onLeave(retval) { if (!this.on) return; libAppTrace.fieldIds[retval.toString()] = `${this.clsName}.${this.name}${this.sig}`; log(`[JNI resolver] GetFieldID -> ${retval} ${libAppTrace.fieldIds[retval.toString()]}`); }
    }));

    hookJni(JNI_GET_STATIC_FIELD_ID_OFF, 'GetStaticFieldID', () => ({
      onEnter(args) { if (!shouldLogNative()) return; this.on = true; this.clazz = args[1]; this.name = jniCString(args[2]); this.sig = jniCString(args[3]); this.clsName = tryGetJClassName(args[0], this.clazz); log(`[JNI resolver] GetStaticFieldID class=${JSON.stringify(this.clsName)} name=${JSON.stringify(this.name)} sig=${JSON.stringify(this.sig)}`); },
      onLeave(retval) { if (!this.on) return; libAppTrace.fieldIds[retval.toString()] = `${this.clsName}.${this.name}${this.sig} [static]`; log(`[JNI resolver] GetStaticFieldID -> ${retval} ${libAppTrace.fieldIds[retval.toString()]}`); }
    }));

    // Do not hook Call*Method by default: dispatcher can call these in tight loops and
    // inline hooks here are noisy/fragile. GetMethodID/GetFieldID + Java-level i() stack
    // is enough to recover the target class/member for most cases.
    log('[LibApp resolver] JNI resolver hooks installed (FindClass/Get*ID only)');
  } catch (e) {
    libAppTrace.jniInstalled = false;
    warn(`[LibApp resolver] JNI hook install failed: ${e}`);
  }
}

function installLibApplicationITracer(reason, attempt) {
  attempt = attempt || 0;
  if (libAppTrace.installed || libAppTrace.installing) return;
  libAppTrace.installing = true;

  const run = () => {
    Java.perform(function () {
      let LibApp = null;
      try {
        LibApp = Java.use(LIBAPP_CLASS);
      } catch (e) {
        libAppTrace.installing = false;
        if (attempt < 80) {
          if ((attempt % 10) === 0) log(`[LibApplication.i hook] ${LIBAPP_CLASS} not ready yet attempt=${attempt} reason=${reason}`);
          setTimeout(function () { installLibApplicationITracer(reason, attempt + 1); }, 250);
        } else {
          warn(`[LibApplication.i hook] class not found after retries: ${e}`);
        }
        return;
      }

      if (!LibApp.i || !LibApp.i.overloads) {
        libAppTrace.installing = false;
        warn(`[LibApplication.i hook] ${LIBAPP_CLASS}.i not found`);
        return;
      }

      if (TRACE_LIBAPP_REFLECTION_RESOLVER) installReflectionResolverHooks();
      if (TRACE_LIBAPP_JNI_RESOLVER) installJniResolverHooksFromCurrentEnv();

      LibApp.i.overloads.forEach(function (ov, idx) {
        const sig = `${ov.returnType.className} i(${ov.argumentTypes.map(t => t.className).join(', ')})`;
        ov.implementation = function () {
          const id = ++libAppTrace.seq;
          const tid = Process.getCurrentThreadId();
          const depthBefore = libAppDepth(tid);
          libAppEnterDepth(tid);
          const opcodeNum = tryOpcodeNumber(arguments);
          const opcode = tryExtractOpcode(arguments);
          const resolveThis = (TRACE_LIBAPP_FOCUS_OPCODES.length === 0) || opcodeIsFocused(opcodeNum) || libAppResolveDepth(tid) > 0;
          const logThis = TRACE_LIBAPP_LOG_ALL_CALLS || resolveThis;
          if (resolveThis) libAppEnterResolve(tid);
          this.__libAppResolveThis = resolveThis;
          this.__libAppLogThis = logThis;
          if (logThis) {
            log(`\n[LibApplication.i enter #${id}] tid=${tid} depth=${depthBefore + 1} overload=${idx} sig=${sig} opcode=${opcode}`);
            log(`[LibApplication.i args #${id}] ${libAppArgsSummary(arguments)}`);
            if (TRACE_LIBAPP_JAVA_STACK) log(`[LibApplication.i java-stack #${id}]\n${javaStackShort()}`);
          }
          let ret = null;
          let threw = null;
          try {
            ret = ov.apply(this, arguments);
            return ret;
          } catch (e) {
            threw = e;
            throw e;
          } finally {
            if (this.__libAppLogThis) {
              if (threw !== null) log(`[LibApplication.i throw #${id}] ${threw}`);
              else log(`[LibApplication.i leave #${id}] ret=${describeJavaValue(ret)}`);
            }
            if (this.__libAppResolveThis) libAppLeaveResolve(tid);
            libAppLeaveDepth(tid);
          }
        };
      });

      libAppTrace.installed = true;
      libAppTrace.installing = false;
      log(`[LibApplication.i hook] installed ${LibApp.i.overloads.length} overload(s), reason=${reason}`);
    });
  };

  try {
    if (Java.available && Java.performNow) Java.performNow(run);
    else run();
  } catch (e) {
    libAppTrace.installing = false;
    warn(`[LibApplication.i hook] install failed now, retrying async: ${e}`);
    setTimeout(function () { installLibApplicationITracer(reason, attempt + 1); }, 250);
  }
}

function installOuterHooks(path) {
  const m = findTargetModule(path);
  if (m === null) {
    warn(`[${TARGET_LIB}] module not visible yet path=${path}`);
    return;
  }
  const key = m.base.toString();
  if (installedOuterBases.has(key)) return;
  installedOuterBases.add(key);

  log(`[${TARGET_LIB}] base=${m.base} path=${m.path}`);
  outerHiddenReturnAddress = m.base.add(DP_JNI_ONLOAD_RET_AFTER_HIDDEN_RVA);
  log(`[outer] expected hidden return/qword_8CEF0=${outerHiddenReturnAddress}`);

  // Direct return-site hooks: entry onLeave can be skipped because we restore LR for safety.
  // These execute immediately before outer JNI_OnLoad returns to ART.
  attachOnce(m.base.add(ptr('0x454')), 'outer JNI_OnLoad early-error epilogue x0', {
    onEnter() {
      log(`[outer JNI_OnLoad RETSITE early] pc=${this.context.pc} x0=${this.context.x0} signed=${this.context.x0.toInt32()}`);
    }
  });
  attachOnce(m.base.add(ptr('0x480')), 'outer JNI_OnLoad normal epilogue x0', {
    onEnter() {
      const v = this.context.x0.toInt32();
      const ok = v === 0x10004 || v === 0x10006;
      log(`[outer JNI_OnLoad RETSITE normal] pc=${this.context.pc} x0=${this.context.x0} signed=${v} valid=${ok}`);
      if (ok) {
        try {
          installLibApplicationITracer(`outer JNI_OnLoad ret-site x0=0x${v.toString(16)}`, 0);
        } catch (e) {
          warn(`[outer JNI_OnLoad RETSITE normal] LibApplication.i tracer install failed: ${e}`);
        }
      }
    }
  });

  attachOnce(m.base.add(DP_JNI_ONLOAD_RVA), 'outer JNI_OnLoad entry/leave', {
    onEnter(args) {
      this.id = ++seq;
      this.realReturnAddress = this.returnAddress || this.context.lr;
      try {
        // Function-entry Interceptor can perturb LR. JNI_OnLoad saves LR in its first
        // instruction, so restore x30 before the prologue executes.
        if (this.realReturnAddress && !this.realReturnAddress.isNull()) {
          this.context.lr = this.realReturnAddress;
          outerJniOnLoadReturnByTid[this.threadId] = this.realReturnAddress;
        }
      } catch (_) {}
      let status = null, entry = null;
      try { status = m.base.add(DP_DWORD_B228_RVA).readS32(); } catch (_) {}
      try { entry = m.base.add(DP_OFF_B230_RVA).readPointer(); } catch (_) {}
      log(`\n[outer JNI_OnLoad enter #${this.id}] vm=${args[0]} reserved=${args[1]} ret=${this.realReturnAddress} dword_B228=${status} off_B230=${entry}`);
      installRegisterNativesTraceFromJvm(args[0], 'outer JNI_OnLoad');
    },
    onLeave(retval) {
      log(`[outer JNI_OnLoad leave #${this.id}] ret=${retval} signed=${retval.toInt32()} valid=${retval.toInt32() === 0x10004 || retval.toInt32() === 0x10006}`);
    }
  });

  const active918 = {};
  attachOnce(m.base.add(DP_SUB_918_RVA), 'outer sub_918 entry/leave', {
    onEnter(args) {
      this.tid = this.threadId;
      this.out = args[0];
      this.rdebug = args[1];
      const info = rDebugInfo(this.rdebug);
      active918[this.tid] = {
        out: this.out,
        rdebug: this.rdebug,
        rawKey: null,
        forcedKey: null,
      };
      log(`[outer sub_918 enter] out=${this.out} r_debug=${this.rdebug} r_brk=${info.rbrk} skip_bti=${info.skipBti} r_brk16=${info.raw16}`);
      if (info.used4 !== null) log(`[outer sub_918 r_brk mix] used_ptr=${info.usedPtr} used4=${hexBytes(info.used4)}`);
      if (info.err !== null) log(`[outer sub_918 r_brk err] ${info.err}`);
    },
    onLeave(retval) {
      const st = active918[this.tid];
      if (SPOOF_OUTER_KEY && st && st.forcedKey !== null) {
        const cur = readBytes(st.out, 32);
        if (!bytesEq(cur, st.forcedKey)) {
          try {
            writeBytes(st.out, st.forcedKey);
            retval.replace(st.out);
            log(`[outer sub_918 spoofed_leave] wrote_forced_key=${hexBytes(st.forcedKey)} retval=${retval}`);
          } catch (e) {
            warn(`[outer sub_918 spoofed_leave] write failed: ${e}`);
          }
        }
      }
      const finalKey = readBytes(this.out, 32);
      log(`[outer sub_918 leave] retval=${retval} final_key=${hexBytes(finalKey)}`);
      delete active918[this.tid];
    }
  });

  // At 0xc98, sub_918 has copied the 32-byte VM/key blob to x0/out,
  // before it XORs r_debug->r_brk bytes. Old working bypass forced
  // those r_brk bytes to ARM64 RET: c0 03 5f d6.
  attachOnce(m.base.add(DP_SUB_918_VM_RAW_COPIED_RVA), 'outer sub_918 raw key', {
    onEnter() {
      const out = this.context.x0;
      const rdebug = this.context.x1;
      const rawKey = readBytes(out, 32);
      const stackRaw = readBytes(this.context.sp, 32);
      const info = rDebugInfo(rdebug);
      const expectedFinal = keyWithRBrkXor(rawKey, info);
      const forcedKey = keyWithFixedRBrkXor(rawKey);
      const tid = this.threadId;
      if (active918[tid] === undefined) active918[tid] = { out, rdebug, rawKey: null, forcedKey: null };
      active918[tid].out = out;
      active918[tid].rdebug = rdebug;
      active918[tid].rawKey = rawKey;
      active918[tid].forcedKey = forcedKey;
      log(`[outer sub_918 vm_raw] out=${out} raw_key=${hexBytes(rawKey)}`);
      log(`[outer sub_918 vm_raw] stack_tmp=${hexBytes(stackRaw)}`);
      log(`[outer sub_918 vm_raw] r_brk=${info.rbrk} skip_bti=${info.skipBti} used4=${info.used4 ? hexBytes(info.used4) : '<none>'} expected_final=${hexBytes(expectedFinal)}`);
      log(`[outer sub_918 spoof_plan] fixed_used4=${hexBytes(SPOOF_RBRK_BYTES)} forced_final=${hexBytes(forcedKey)}`);
    }
  });

  // Exact end of sub_918 before epilogue: overwrite final key here too.
  attachOnce(m.base.add(DP_SUB_918_FINAL_RVA), 'outer sub_918 final site', {
    onEnter() {
      const out = this.context.x0;
      const nativeFinalKey = readBytes(out, 32);
      log(`[outer sub_918 final_site] out=${out} native_final_key=${hexBytes(nativeFinalKey)}`);
      const st = active918[this.threadId];
      if (SPOOF_OUTER_KEY && st && st.forcedKey !== null) {
        try {
          writeBytes(out, st.forcedKey);
          log(`[outer sub_918 spoofed_final_site] forced_key=${hexBytes(st.forcedKey)}`);
        } catch (e) {
          warn(`[outer sub_918 spoofed_final_site] write failed: ${e}`);
        }
      }
    }
  });

  // sub_167C(dynamic, load_bias, auxv, r_debug) happens before hidden init/JNI entry.
  attachOnce(m.base.add(DP_SUB_167C_RVA), 'outer sub_167C get hidden load_bias', {
    onEnter(args) {
      this.loadBias = args[1];
      pendingHiddenLoadBias = this.loadBias;
      log(`[sub_167C enter] hidden_load_bias=${this.loadBias}`);
    },
    onLeave(retval) {
      log(`[sub_167C leave] ret=${retval} hidden_load_bias=${this.loadBias}`);
    }
  });

  // Outer JNI_OnLoad calls hidden entry through:
  //   0x464 LDR X8, [X19,#0x230]  ; hidden entry = hidden_base+0x4E354
  //   0x468 BLR X8
  // This is latest clean point before hidden sub_4E354 runs. Compute digest first, then install hidden hooks.
  attachOnce(m.base.add(DP_JNI_ONLOAD_CALL_HIDDEN_RVA), 'outer JNI_OnLoad before hidden entry', {
    onEnter() {
      const realOuterRet = outerJniOnLoadReturnByTid[this.threadId];
      if (realOuterRet) {
        try {
          const beforeSaved = this.context.sp.readPointer();
          this.context.sp.writePointer(realOuterRet);
          log(`[outer JNI_OnLoad saved LR fix] before=${beforeSaved} forced=${realOuterRet}`);
        } catch (e) {
          warn(`[outer JNI_OnLoad saved LR fix] failed: ${e}`);
        }
      }
      const hiddenEntry = this.context.x8;
      const loadBias = pendingHiddenLoadBias || hiddenEntry.sub(H_SUB_4E354_RVA);
      log(`[outer JNI_OnLoad hidden call] entry=${hiddenEntry} load_bias=${loadBias}`);
      computeRuntimeCleanSub3E038Digest(loadBias);
      computeRuntimeCleanSub16190Hash(loadBias);
      installHiddenHooks(loadBias);
    }
  });

  attachOnce(m.base.add(DP_JNI_ONLOAD_RET_AFTER_HIDDEN_RVA), 'outer JNI_OnLoad after hidden entry', {
    onEnter() {
      const hiddenRet = this.context.x0.toInt32();
      log(`[outer JNI_OnLoad after hidden] hidden_ret=${this.context.x0} signed=${hiddenRet}; outer will return ${hiddenRet === 0 ? 'JNI_VERSION_1_4(0x10004)' : '-' + hiddenRet}`);
      if (FORCE_OUTER_JNI_ONLOAD_SUCCESS && hiddenRet !== 0) {
        this.context.x0 = ptr(0);
        log('[outer JNI_OnLoad FORCE] hidden_ret forced to 0 -> ART sees JNI_VERSION_1_4');
      }
    }
  });

  attachOnce(m.base.add(TARGET_INIT_RVA), 'outer init 0x378', {
    onEnter() { log(`[outer init] ${TARGET_LIB}+0x378 enter`); },
    onLeave(retval) {
      let status = null, entry = null;
      try { status = m.base.add(DP_DWORD_B228_RVA).readS32(); } catch (_) {}
      try { entry = m.base.add(DP_OFF_B230_RVA).readPointer(); } catch (_) {}
      log(`[outer init] ${TARGET_LIB}+0x378 leave ret=${retval} dword_B228=${status} off_B230=${entry}`);
    }
  });
}

function installLinkerConstructorHooks() {
  const linker = findLinkerModule();
  if (!linker) { warn('linker/linker64 not found'); return; }
  log(`[start] linker=${linker.name} base=${linker.base} path=${linker.path}`);

  let syms;
  try { syms = enumSymbols(linker); }
  catch (e) { warn(`cannot enumerate linker symbols: ${e}`); return; }

  const getRealpathSym = syms.find(s => s.type === 'function' && s.name.indexOf('soinfo') !== -1 && s.name.indexOf('get_realpath') !== -1);
  const getSonameSym = syms.find(s => s.type === 'function' && s.name.indexOf('soinfo') !== -1 && s.name.indexOf('get_soname') !== -1);
  const getRealpath = getRealpathSym ? new NativeFunction(getRealpathSym.address, 'pointer', ['pointer']) : null;
  const getSoname = getSonameSym ? new NativeFunction(getSonameSym.address, 'pointer', ['pointer']) : null;

  function soinfoPath(si) {
    for (const f of [getRealpath, getSoname]) {
      if (f === null) continue;
      try {
        const s = safeCString(f(si));
        if (s) return s;
      } catch (_) {}
    }
    return `<soinfo ${si}>`;
  }

  const ctorSyms = syms.filter(s => s.type === 'function' &&
    s.name.indexOf('call_constructors') !== -1 &&
    s.name.indexOf('call_pre_init') === -1 &&
    s.name.indexOf('call_destructors') === -1);

  log(`[start] call_constructors hooks=${ctorSyms.length}`);
  ctorSyms.forEach(s => {
    Interceptor.attach(s.address, {
      onEnter(args) {
        this.path = soinfoPath(args[0]);
        if (isTargetPath(this.path)) {
          log(`[linker call_constructors] target=${this.path}`);
          installOuterHooks(this.path);
        }
      }
    });
  });

  if (ctorSyms.length === 0) warn('No call_constructors symbol found');

  // Attach-mode / race fallback: if target lib is already mapped, install directly.
  const already = Process.findModuleByName(TARGET_LIB);
  if (already !== null) {
    log(`[start] ${TARGET_LIB} already mapped, installing outer hooks directly`);
    installOuterHooks(already.path);
  }
}

// [native-only] Removed installMinimalComponentFactoryBypass Java/JNI diagnostic hook block.

// [native-only] Removed installMinimalGcNoop Java/JNI diagnostic hook block.

function main() {
  mkdirOne(DUMP_DIR);

  // Critical: install linker call_constructors hook synchronously before Frida resumes
  // the spawned app. setImmediate() was too late and missed libdexprotector init.
  installLinkerConstructorHooks();

  // Intentionally no Java hooks here: no provider stub, no factory hook, no GC hook,
  // no LibApplication.i wrapper. Let Android continue naturally after JNI_OnLoad.
  log('[mode] JNI_OnLoad bypass + delayed LibApplication.i resolver trace');

  // Non-critical diagnostics after critical hook is armed.
}

main();
