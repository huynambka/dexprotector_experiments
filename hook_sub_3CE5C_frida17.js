'use strict';

/*
 * Frida 17.x: minimal hook for unpacked libdp init-array function sub_3CE5C.
 * Focus log: decode output stored at unpacked_image+0x891B0.
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks -l hook_sub_3CE5C_frida17.js
 */

const TARGET_LIB = 'libdexprotector.so';
const TARGET_INIT_RVA = ptr('0x378');

// Outer libdexprotector RVAs
const DP_SUB_918_RVA = ptr('0x918');
const DP_SUB_918_VM_RAW_COPIED_RVA = ptr('0xc98');
const DP_SUB_918_FINAL_RVA = ptr('0xd34');
const DP_SUB_167C_RVA = ptr('0x167c');

// Unpacked image RVAs
const UNPACKED_SUB_3CE5C_RVA = ptr('0x3ce5c');
const UNPACKED_QWORD_891B0_RVA = ptr('0x891b0');
const DECODED_LEN = 0x6c;

// Same spoof used before: final_key = raw_key ^ bytes(c0 03 5f d6)
const SPOOF_SUB_918 = true;
const SPOOF_RBRK_BYTES = [0xc0, 0x03, 0x5f, 0xd6];

const hooked = new Set();
const installedOuterBases = new Set();
const installedUnpackedBases = new Set();
let depth = 0;

function log(s) { console.log(s); }
function warn(s) { console.warn(s); }

function ptrNum(p) {
  try { return parseInt(p.toString(), 16); } catch (_) { return 0; }
}

function safeCString(p) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    return p.readCString();
  } catch (_) { return null; }
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

function describeAddress(p) {
  if (p === null || p === undefined || p.isNull()) return String(p);
  const m = Process.findModuleByAddress(p);
  if (m === null) return p.toString();
  return `${p} ${m.name}+0x${p.sub(m.base).toString(16)}`;
}

function readBytes(p, len) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    const ab = p.readByteArray(len);
    if (ab === null) return null;
    return Array.from(new Uint8Array(ab));
  } catch (_) { return null; }
}

function bytesToHex(bytes) {
  if (bytes === null) return '<read failed>';
  return bytes.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

function bytesToAsciiPreview(bytes) {
  if (bytes === null) return '<read failed>';
  const s = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] & 0xff;
    if (b >= 0x20 && b <= 0x7e && b !== 0x5c) s.push(String.fromCharCode(b));
    else if (b === 0x5c) s.push('\\\\');
    else if (b === 0x00) s.push('\\0');
    else if (b === 0x0a) s.push('\\n');
    else if (b === 0x0d) s.push('\\r');
    else if (b === 0x09) s.push('\\t');
    else s.push('.');
  }
  return s.join('');
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

function attachOnce(addr, label, handlers) {
  const k = `${label}@${addr}`;
  if (hooked.has(k)) return;
  hooked.add(k);
  Interceptor.attach(addr, handlers);
}

function installSub3CE5CHook(loadBias) {
  const key = loadBias.toString();
  if (installedUnpackedBases.has(key)) return;
  installedUnpackedBases.add(key);

  const fn = loadBias.add(UNPACKED_SUB_3CE5C_RVA);
  const globalPtrPtr = loadBias.add(UNPACKED_QWORD_891B0_RVA);

  log(`[unpacked] load_bias=${loadBias} hook sub_3CE5C=${fn}`);

  attachOnce(fn, 'unpacked_sub_3CE5C', {
    onEnter() {
      this.globalBefore = ptr(0);
      try { this.globalBefore = globalPtrPtr.readPointer(); } catch (_) {}
      log(`[sub_3CE5C enter] qword_891B0_before=${this.globalBefore}`);
    },
    onLeave(retval) {
      let decodedPtr = ptr(0);
      try { decodedPtr = globalPtrPtr.readPointer(); } catch (_) {}

      const retBytes = readBytes(retval, DECODED_LEN);
      const globalBytes = readBytes(decodedPtr, DECODED_LEN);
      const useBytes = globalBytes !== null ? globalBytes : retBytes;

      log(`[sub_3CE5C leave] ret=${retval} qword_891B0=${decodedPtr}`);
      log(`[sub_3CE5C decoded ${DECODED_LEN}B hex] ${bytesToHex(useBytes)}`);
      log(`[sub_3CE5C decoded ascii] ${bytesToAsciiPreview(useBytes)}`);
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
    onEnter(args) {
      active918[this.threadId] = { out: args[0], forcedKey: null };
    },
    onLeave(retval) {
      const st = active918[this.threadId];
      if (SPOOF_SUB_918 && st && st.forcedKey !== null) {
        try { writeBytes(st.out, st.forcedKey); retval.replace(st.out); } catch (_) {}
      }
      delete active918[this.threadId];
    }
  });

  // Raw key exists here before native XOR with r_debug->r_brk. Build forced final key.
  attachOnce(vmRawCopied, 'sub_918_raw_key', {
    onEnter() {
      const out = this.context.x0;
      const rawKey = readBytes(out, 32);
      const forcedKey = keyWithFixedRBrkXor(rawKey);
      if (active918[this.threadId] === undefined) active918[this.threadId] = { out, forcedKey: null };
      active918[this.threadId].out = out;
      active918[this.threadId].forcedKey = forcedKey;
      if (rawKey !== null && forcedKey !== null) {
        log(`[sub_918] raw=${bytesToHex(rawKey)} forced=${bytesToHex(forcedKey)}`);
      }
    }
  });

  // Write forced final key before sub_918 returns.
  attachOnce(finalSite, 'sub_918_final_site', {
    onEnter() {
      const st = active918[this.threadId];
      if (SPOOF_SUB_918 && st && st.forcedKey !== null) {
        try { writeBytes(this.context.x0, st.forcedKey); } catch (_) {}
      }
    }
  });

  // sub_167C(dynamic, load_bias, auxv, r_debug) runs before init_array.
  // Hook sub_3CE5C as soon as we learn load_bias.
  attachOnce(sub167c, 'sub_167C_get_load_bias', {
    onEnter(args) {
      this.loadBias = args[1];
      installSub3CE5CHook(this.loadBias);
    },
    onLeave(retval) {
      log(`[sub_167C leave] ret=${retval} load_bias=${this.loadBias}`);
    }
  });
}

function installOuterHooks(path) {
  const m = findTargetModule(path);
  if (m === null) {
    warn(`[${TARGET_LIB}] module not visible yet`);
    return;
  }

  const baseKey = m.base.toString();
  if (installedOuterBases.has(baseKey)) return;
  installedOuterBases.add(baseKey);

  log(`[${TARGET_LIB}] base=${m.base}`);

  // Tiny confirmation that the original constructor ran.
  attachOnce(m.base.add(TARGET_INIT_RVA), 'outer_init_378', {
    onEnter() { log(`[outer init] ${TARGET_LIB}+0x378 enter`); },
    onLeave() { log(`[outer init] ${TARGET_LIB}+0x378 leave`); }
  });

  installSub918SpoofAndRelocHook(m);
}

function main() {
  const linker = findLinkerModule();
  if (!linker) {
    warn('linker/linker64 not found');
    return;
  }

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
        this.d = depth++;
        if (isTargetPath(this.path)) {
          log(`[linker ctor] target path=${this.path}`);
          installOuterHooks(this.path);
        }
      },
      onLeave() {
        depth--;
      }
    });
  });

  if (ctorSyms.length === 0) warn('No call_constructors symbol found in linker');
}

setImmediate(main);
