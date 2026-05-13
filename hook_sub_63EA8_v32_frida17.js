'use strict';

/*
 * Frida 17.x: hook unpacked-image sub_63EA8 and print stack buffer v32 onLeave.
 *
 * sub_63EA8 frame:
 *   entry SP -> prologue saves 0x40, then allocates 0x1020
 *   v32      = entry_sp - 0x1060  (x19 after prologue)
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l hook_sub_63EA8_v32_frida17.js
 */

const TARGET_LIB = 'libdexprotector.so';
const TARGET_INIT_RVA = ptr('0x378');

// Outer libdexprotector.so RVAs, used to reach hidden/unpacked image reliably.
const DP_SUB_918_RVA = ptr('0x918');
const DP_SUB_918_VM_RAW_COPIED_RVA = ptr('0xc98');
const DP_SUB_918_FINAL_RVA = ptr('0xd34');
const DP_SUB_167C_RVA = ptr('0x167c');
const SPOOF_SUB_918 = true;
const SPOOF_RBRK_BYTES = [0xc0, 0x03, 0x5f, 0xd6]; // ARM64 ret bytes

// Hidden/unpacked image RVAs.
const SUB_63EA8_RVA = ptr('0x63ea8');
const SUB_63EA8_LOG_CALLSITE_RVA = ptr('0x640e8'); // optional: BLR x21 => __android_log_btwrite(30014, 2, v32)
const PRINT_CALLSITE = true;
const PRINT_ONLEAVE = false; // onLeave stack buffer may already be stale/reused

// entry_sp - 0x40(saved regs) - 0x1020(local area) = v32
const V32_FROM_ENTRY_SP = 0x1060;
const V32_SHOW_SIZE = 0x1020;

const hooked = new Set();
const installedOuterBases = new Set();
const installedUnpackedBases = new Set();
let currentLoadBias = null;
let seq = 0;

function log(s) { console.log(s); }
function warn(s) { console.warn(s); }

function safeCString(p, maxLen) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    if (maxLen !== undefined) return p.readCString(maxLen);
    return p.readCString();
  } catch (_) { return null; }
}

function readBytes(p, len) {
  try {
    if (p === null || p === undefined || p.isNull() || len <= 0) return null;
    const ab = p.readByteArray(len);
    if (ab === null) return null;
    return Array.from(new Uint8Array(ab));
  } catch (_) { return null; }
}

function bytesToHex(bytes) {
  if (bytes === null) return '<read failed>';
  return bytes.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

function bytesToPrintable(bytes) {
  if (bytes === null) return '<read failed>';
  let s = '';
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
    else if (b === 0x09) s += '\t';
    else if (b === 0x0a) s += '\n';
    else if (b === 0x0d) s += '\r';
    else s += `\\x${('0' + (b & 0xff).toString(16)).slice(-2)}`;
  }
  return s;
}

function sanitize(s) {
  if (s === null || s === undefined) return '<read failed>';
  return JSON.stringify(String(s).replace(/\n/g, '\\n').replace(/\r/g, '\\r'));
}

function safeU32(p) {
  try { return p.readU32(); } catch (_) { return null; }
}

function dumpV32(tag, p, retval) {
  const len32 = safeU32(p);
  const first64 = readBytes(p, 64);
  const lenText = len32 === null ? '<read failed>' : `0x${len32.toString(16)} (${len32})`;

  log(`[${tag}] ret=${retval} v32=${p} len32=${lenText}`);

  // __android_log_btwrite(type=2) expects binary payload:
  //   u32 length; char bytes[length]
  // So do NOT read a C string starting at v32; skip the 4-byte binary length.
  if (len32 !== null && len32 > 0 && len32 < 0x1000) {
    const payload = readBytes(p.add(4), len32);
    log(`  payload_ascii=${JSON.stringify(bytesToPrintable(payload))}`);
    log(`  payload_hex=${bytesToHex(payload)}`);
  } else {
    const strAfterLen = safeCString(p.add(4), V32_SHOW_SIZE - 4);
    log(`  cstr@v32+4=${sanitize(strAfterLen)}`);
  }
  log(`  first64_hex=${bytesToHex(first64)}`);
}

function writeBytes(p, bytes) {
  const u8 = new Uint8Array(bytes);
  p.writeByteArray(u8.buffer);
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
  const mods = Process.enumerateModules();
  return mods.find(x => x.path === path || x.path.indexOf(TARGET_LIB) !== -1 || x.name === TARGET_LIB) || null;
}

function attachOnce(addr, label, handlers) {
  const k = `${label}@${addr}`;
  if (hooked.has(k)) return;
  hooked.add(k);
  Interceptor.attach(addr, handlers);
}

function installUnpackedHooks(loadBias) {
  const key = loadBias.toString();
  if (installedUnpackedBases.has(key)) return;
  installedUnpackedBases.add(key);
  currentLoadBias = loadBias;

  const sub63 = loadBias.add(SUB_63EA8_RVA);
  const callsite = loadBias.add(SUB_63EA8_LOG_CALLSITE_RVA);
  log(`[unpacked] load_bias=${loadBias}`);
  log(`[unpacked] hook sub_63EA8=${sub63}`);

  attachOnce(sub63, 'sub_63EA8_onLeave_v32', {
    onEnter(args) {
      this.id = ++seq;
      this.a1 = args[0];
      this.v32 = this.context.sp.sub(V32_FROM_ENTRY_SP);
      const a1s = safeCString(this.a1, 256);
      log(`\n[sub_63EA8 enter #${this.id}] a1=${this.a1} a1_str=${sanitize(a1s)} v32(pred)=${this.v32}`);
    },
    onLeave(retval) {
      if (PRINT_ONLEAVE) dumpV32(`sub_63EA8 leave #${this.id}`, this.v32, retval);
      else log(`[sub_63EA8 leave #${this.id}] ret=${retval} (payload printed at btwrite callsite if reached)`);
    }
  });

  // Optional checkpoint right before __android_log_btwrite. Here x2 is exactly v32,
  // and v32[0] has already been overwritten with payload length.
  if (PRINT_CALLSITE) {
    attachOnce(callsite, 'sub_63EA8_before_btwrite', {
      onEnter() {
        dumpV32('sub_63EA8 before __android_log_btwrite', this.context.x2, ptr('0x0'));
      }
    });
  }
}

function installSub918SpoofAndRelocHook(m) {
  const sub918 = m.base.add(DP_SUB_918_RVA);
  const vmRawCopied = m.base.add(DP_SUB_918_VM_RAW_COPIED_RVA);
  const finalSite = m.base.add(DP_SUB_918_FINAL_RVA);
  const sub167c = m.base.add(DP_SUB_167C_RVA);
  const active918 = {};

  attachOnce(sub918, 'sub_918_entry_leave', {
    onEnter(args) { active918[this.threadId] = { out: args[0], forcedKey: null }; },
    onLeave(retval) {
      const st = active918[this.threadId];
      if (SPOOF_SUB_918 && st && st.forcedKey !== null) {
        try { writeBytes(st.out, st.forcedKey); retval.replace(st.out); } catch (_) {}
      }
      delete active918[this.threadId];
    }
  });

  attachOnce(vmRawCopied, 'sub_918_raw_key', {
    onEnter() {
      const out = this.context.x0;
      const rawKey = readBytes(out, 32);
      const forcedKey = keyWithFixedRBrkXor(rawKey);
      if (active918[this.threadId] === undefined) active918[this.threadId] = { out, forcedKey: null };
      active918[this.threadId].out = out;
      active918[this.threadId].forcedKey = forcedKey;
      if (rawKey !== null && forcedKey !== null) log(`[sub_918] forced key=${bytesToHex(forcedKey)}`);
    }
  });

  attachOnce(finalSite, 'sub_918_final_site', {
    onEnter() {
      const st = active918[this.threadId];
      if (SPOOF_SUB_918 && st && st.forcedKey !== null) {
        try { writeBytes(this.context.x0, st.forcedKey); } catch (_) {}
      }
    }
  });

  // sub_167C(dynamic, load_bias, auxv, r_debug). x1 = unpacked hidden image load bias.
  attachOnce(sub167c, 'sub_167C_get_load_bias', {
    onEnter(args) {
      this.loadBias = args[1];
      installUnpackedHooks(this.loadBias);
    },
    onLeave(retval) { log(`[sub_167C leave] ret=${retval} load_bias=${this.loadBias}`); }
  });
}

function installOuterHooks(path) {
  const m = findTargetModule(path);
  if (m === null) { warn(`[${TARGET_LIB}] module not visible yet`); return; }

  const baseKey = m.base.toString();
  if (installedOuterBases.has(baseKey)) return;
  installedOuterBases.add(baseKey);

  log(`[${TARGET_LIB}] base=${m.base}`);
  attachOnce(m.base.add(TARGET_INIT_RVA), 'outer_init_378', {
    onEnter() { log(`[outer init] ${TARGET_LIB}+0x378 enter`); },
    onLeave() { log(`[outer init] ${TARGET_LIB}+0x378 leave`); }
  });
  installSub918SpoofAndRelocHook(m);
}

function main() {
  const linker = findLinkerModule();
  if (!linker) { warn('linker/linker64 not found'); return; }

  let syms;
  try { syms = enumSymbols(linker); }
  catch (e) { warn('cannot enumerate linker symbols: ' + e); return; }

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

  log(`[start] linker=${linker.name} ctor_hooks=${ctorSyms.length}`);
  ctorSyms.forEach(s => {
    Interceptor.attach(s.address, {
      onEnter(args) {
        this.path = soinfoPath(args[0]);
        if (isTargetPath(this.path)) {
          log(`[linker ctor] target path=${this.path}`);
          installOuterHooks(this.path);
        }
      }
    });
  });

  if (ctorSyms.length === 0) warn('No call_constructors symbol found in linker');
}

setImmediate(main);
