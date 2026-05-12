'use strict';

/*
 * Frida 17.x: print v0/v1 in sub_363F0:
 *
 *   v0 = decode(dword_3991, v17, 8);
 *   v1 = decode(dword_3406, v16, 22);
 *   v2 = sub_3B614(v0, v1);
 *
 * We avoid hooking decode/sub_401B0 because it self-checks its first bytes.
 * Instead we hook sub_3B614 and filter the call from sub_363F0+0x44
 * where x0=v0 and x1=v1.
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l hook_sub_363F0_decode_v0_v1_frida17.js
 */

const TARGET_LIB = 'libdexprotector.so';
const TARGET_INIT_RVA = ptr('0x378');

// Outer libdexprotector.so RVAs, needed to reach unpacked payload reliably.
const DP_SUB_918_RVA = ptr('0x918');
const DP_SUB_918_VM_RAW_COPIED_RVA = ptr('0xc98');
const DP_SUB_918_FINAL_RVA = ptr('0xd34');
const DP_SUB_167C_RVA = ptr('0x167c');
const SPOOF_SUB_918 = true;
const SPOOF_RBRK_BYTES = [0xc0, 0x03, 0x5f, 0xd6]; // ARM64 ret bytes

// Unpacked image RVAs.
const SUB_363F0_RVA = ptr('0x363f0');
const SUB_363F0_END = ptr('0x36600');
const SUB_3B614_RVA = ptr('0x3b614');
const SUB_3B614_RET_FROM_363F0 = ptr('0x36438'); // return address after BL sub_3B614

const hooked = new Set();
const installedOuterBases = new Set();
const installedUnpackedBases = new Set();

let currentLoadBias = null;
let callNo = 0;

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

function bytesToAscii(bytes) {
  if (bytes === null) return '<read failed>';
  let s = '';
  for (const b of bytes) {
    if (b === 0) break;
    s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.';
  }
  return s;
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

function moduleDesc(p) {
  try {
    if (typeof Process.findModuleByAddress === 'function') {
      const m = Process.findModuleByAddress(p);
      if (m !== null) return `${m.name}+0x${p.sub(m.base).toString(16)} ${m.path}`;
    }
  } catch (_) {}
  try {
    const r = Process.findRangeByAddress(p);
    if (r !== null) return `${r.protection} ${r.base}-0x${r.base.add(r.size).toString(16)}`;
  } catch (_) {}
  return '<unknown>';
}

function isLrFromSub363F0(lr) {
  if (currentLoadBias === null) return false;
  try {
    const off = lr.sub(currentLoadBias);
    return off.compare(SUB_363F0_RVA) >= 0 && off.compare(SUB_363F0_END) < 0;
  } catch (_) { return false; }
}

function rvaOf(p) {
  if (currentLoadBias === null) return '<no-bias>';
  try { return '0x' + p.sub(currentLoadBias).toString(16); } catch (_) { return '<bad>'; }
}

function fmtDecoded(name, p, fixedLen) {
  const b = readBytes(p, fixedLen);
  const cstr = safeCString(p, fixedLen);
  return `${name}=${p} ascii="${bytesToAscii(b)}" cstr=${JSON.stringify(cstr)} fixed${fixedLen}_hex=${bytesToHex(b)}`;
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

  const sub363 = loadBias.add(SUB_363F0_RVA);
  const sub3b614 = loadBias.add(SUB_3B614_RVA);
  log(`[unpacked] load_bias=${loadBias}`);
  log(`[unpacked] hook sub_363F0=${sub363} sub_3B614=${sub3b614}`);

  attachOnce(sub363, 'sub_363F0_entry_leave', {
    onEnter() {
      log('\n[sub_363F0 enter] about to resolve v2 = sub_3B614(v0, v1)');
    },
    onLeave(retval) {
      log(`[sub_363F0 leave] ret=${retval}`);
      log('--- end sub_363F0 ---\n');
    }
  });

  attachOnce(sub3b614, 'sub_3B614_filtered_from_363F0', {
    onEnter(args) {
      this.active = isLrFromSub363F0(this.context.lr);
      if (!this.active) return;

      this.seq = ++callNo;
      this.v0 = args[0];
      this.v1 = args[1];
      const lrRva = rvaOf(this.context.lr);

      log(`[sub_3B614 enter #${this.seq}] caller=${this.context.lr} (${lrRva})`);
      log(`  ${fmtDecoded('v0 / dword_3991 len=8 ', this.v0, 8)}`);
      log(`  ${fmtDecoded('v1 / dword_3406 len=22', this.v1, 22)}`);
    },
    onLeave(retval) {
      if (!this.active) return;
      log(`[sub_3B614 leave #${this.seq}] v2/ret=${retval} // ${moduleDesc(retval)}`);
      if (!retval.isNull()) {
        log(`  resolved target likely function pointer for ${safeCString(this.v1, 22)} in ${safeCString(this.v0, 8)}`);
      }
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

  // sub_167C(dynamic, load_bias, auxv, r_debug); load_bias is enough to hook unpacked image.
  attachOnce(sub167c, 'sub_167C_get_load_bias', {
    onEnter(args) {
      this.loadBias = args[1];
      installUnpackedHooks(this.loadBias);
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
