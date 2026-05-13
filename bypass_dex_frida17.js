'use strict';

/*
 * Frida 17.x: bypass hidden image integrity check by spoofing sub_16190's
 * return value to qword_8CEF8 when called from sub_4E354+0x294.
 *
 * Real code:
 *   X20 = qword_8CEF8;
 *   X0  = sub_16190(qword_84B20, qword_84B88-qword_84B20, zero_key);
 *   CMP X20, X0
 *   B.EQ ok
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l bypass_dex_frida17.js
 */

const TARGET_LIB = 'libdexprotector.so';
const TARGET_INIT_RVA = ptr('0x378');

// Outer libdexprotector.so RVAs.
const DP_SUB_918_RVA = ptr('0x918');
const DP_SUB_918_VM_RAW_COPIED_RVA = ptr('0xc98');
const DP_SUB_918_FINAL_RVA = ptr('0xd34');
const DP_SUB_167C_RVA = ptr('0x167c');
const SPOOF_SUB_918 = true;
const SPOOF_RBRK_BYTES = [0xc0, 0x03, 0x5f, 0xd6];

// Hidden/unpacked image RVAs.
const SUB_16190_RVA = ptr('0x16190');
const CALLER_RET_AFTER_SUB16190_RVA = ptr('0x4e5e8');
const QWORD_8CEF8_RVA = ptr('0x8cef8');
const QWORD_84B20_RVA = ptr('0x84b20');
const QWORD_84B88_RVA = ptr('0x84b88');
const SUB_15DD4_RVA = ptr('0x15dd4');
const CALLER_RET_AFTER_SUB15DD4_RVA = ptr('0x4e638');
const EXPECTED_MAGIC_4E354 = [0x8f, 0xf9, 0xa6, 0xbe];

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

function writeBytes(p, bytes) {
  const u8 = new Uint8Array(bytes);
  p.writeByteArray(u8.buffer);
}

function tryWriteBytes(p, bytes) {
  try { writeBytes(p, bytes); return true; } catch (_) { return false; }
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

function ptrHex(p) { try { return '0x' + p.toString(16); } catch (_) { return String(p); } }

function rvaOf(p) {
  if (currentLoadBias === null) return '<no-bias>';
  try { return ptr('0x' + p.sub(currentLoadBias).toString(16)); } catch (_) { return null; }
}

function samePtr(a, b) {
  try { return a.compare(b) === 0; } catch (_) { return false; }
}

function readU64Ptr(addr) {
  try { return addr.readPointer(); } catch (_) { return null; }
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

  const sub16190 = loadBias.add(SUB_16190_RVA);
  const sub15dd4 = loadBias.add(SUB_15DD4_RVA);
  const wantedRetAddr = loadBias.add(CALLER_RET_AFTER_SUB16190_RVA);
  const wantedMagicRetAddr = loadBias.add(CALLER_RET_AFTER_SUB15DD4_RVA);
  const expectedAddr = loadBias.add(QWORD_8CEF8_RVA);
  const rangeStartAddr = loadBias.add(QWORD_84B20_RVA);
  const rangeEndAddr = loadBias.add(QWORD_84B88_RVA);

  log(`[unpacked] load_bias=${loadBias}`);
  log(`[integrity] hook sub_16190=${sub16190}`);
  log(`[integrity] hook sub_15DD4=${sub15dd4} magic retaddr=${wantedMagicRetAddr}`);
  log(`[integrity] expected qword_8CEF8 @ ${expectedAddr} = ${readU64Ptr(expectedAddr)}`);
  log(`[integrity] hash range ptrs: qword_84B20=${readU64Ptr(rangeStartAddr)} qword_84B88=${readU64Ptr(rangeEndAddr)}`);

  attachOnce(sub16190, 'sub_16190_spoof_expected_from_4E354', {
    onEnter(args) {
      this.id = ++seq;
      this.lr = this.context.lr;
      this.isIntegrityCall = samePtr(this.lr, wantedRetAddr);
      this.expected = readU64Ptr(expectedAddr);

      if (this.isIntegrityCall) {
        log(`\n[sub_16190 integrity ENTER #${this.id}] lr=${this.lr} args: data=${args[0]} len=${args[1]} key=${args[2]}`);
      }
    },
    onLeave(retval) {
      if (!this.isIntegrityCall) return;
      log(`[sub_16190 integrity LEAVE #${this.id}] real_ret=${retval} expected=${this.expected}`);
      if (this.expected !== null) {
        retval.replace(this.expected);
        log(`[sub_16190 integrity SPOOF #${this.id}] ret -> ${this.expected}`);
      } else {
        warn(`[sub_16190 integrity] failed to read qword_8CEF8; not spoofing`);
      }
    }
  });


  // Bypass magic branch after sub_15DD4 in sub_4E354:
  // expected v52 bytes are 8f f9 a6 be. sub_15DD4 args:
  //   x0=ctx, x1=&const64, x2=8, x3=&v52, x4=4
  // Force the output buffer so all byte compares pass and loc_4E688 is skipped.
  attachOnce(sub15dd4, 'sub_15DD4_force_magic_from_4E354', {
    onEnter(args) {
      this.id = ++seq;
      this.lr = this.context.lr;
      this.isMagicCall = samePtr(this.lr, wantedMagicRetAddr);
      this.out = args[3];
      this.outLen = args[4];
      if (this.isMagicCall) {
        log(`\n[sub_15DD4 magic ENTER #${this.id}] lr=${this.lr} out=${this.out} outLen=${this.outLen}`);
      }
    },
    onLeave(retval) {
      if (!this.isMagicCall) return;
      const before = readBytes(this.out, 4);
      const ok = tryWriteBytes(this.out, EXPECTED_MAGIC_4E354);
      const after = readBytes(this.out, 4);
      log(`[sub_15DD4 magic LEAVE #${this.id}] ret=${retval} before=${bytesToHex(before)} forced=${bytesToHex(EXPECTED_MAGIC_4E354)} ok=${ok} after=${bytesToHex(after)}`);
    }
  });
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

  // sub_167C(dynamic, load_bias, auxv, r_debug). x1 = hidden image load bias.
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
