'use strict';

/*
 * Frida 17.x: hook one function in the unpacked DexProtector hidden image
 * by RVA/offset, then print arguments and return value.
 *
 * Usage example:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -P '{"offset":"0x4E354","argc":4,"hexdump":32,"backtrace":false}' \
 *     -l hook_unpacked_fn_args_ret_frida17.js
 *
 * Parameters (-P JSON):
 *   offset / rva : required, unpacked-image RVA, e.g. "0x4E354"
 *   argc         : optional, how many args to print, default 8
 *   hexdump      : optional, for pointer args dump N bytes, default 0
 *   cstring      : optional, try reading printable C string, default true
 *   backtrace    : optional, print native backtrace on enter, default false
 *   maxCalls     : optional, 0 = unlimited, default 0
 *   label        : optional, log label, default "unpacked+<offset>"
 *   spoof_key    : optional, spoof outer sub_918 key, default true
 */

const TARGET_LIB = 'libdexprotector.so';
const TARGET_INIT_RVA = ptr('0x378');

// Outer libdexprotector.so RVAs, needed to reach unpacked payload reliably.
const DP_SUB_918_RVA = ptr('0x918');
const DP_SUB_918_VM_RAW_COPIED_RVA = ptr('0xc98');
const DP_SUB_918_FINAL_RVA = ptr('0xd34');
const DP_SUB_167C_RVA = ptr('0x167c');
const SPOOF_RBRK_BYTES = [0xc0, 0x03, 0x5f, 0xd6]; // ARM64 ret bytes

const hooked = new Set();
const installedOuterBases = new Set();
const installedUnpackedBases = new Set();

let currentLoadBias = null;
let started = false;
let configured = false;
let targetListener = null;
let callSeq = 0;

const cfg = {
  rva: null,
  argc: 8,
  hexdump: 0,
  cstring: true,
  backtrace: false,
  maxCalls: 0,
  label: null,
  spoofKey: true,
};

function log(s) { console.log(s); }
function warn(s) { console.warn(s); }

function parseBool(v, dflt) {
  if (v === undefined || v === null) return dflt;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v !== 0;
  const s = String(v).toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].indexOf(s) !== -1) return true;
  if (['0', 'false', 'no', 'n', 'off'].indexOf(s) !== -1) return false;
  return dflt;
}

function parseNum(v, dflt) {
  if (v === undefined || v === null || v === '') return dflt;
  if (typeof v === 'number') return v;
  const s = String(v).trim();
  if (s.startsWith('0x') || s.startsWith('0X')) return parseInt(s, 16);
  return parseInt(s, 10);
}

function parsePtrValue(v) {
  if (v === undefined || v === null || v === '') return null;
  let s = String(v).trim();
  if (s[0] === '+') s = s.slice(1);
  return ptr(s);
}

function safeCString(p, maxLen) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    if (maxLen !== undefined) return p.readCString(maxLen);
    return p.readCString();
  } catch (_) { return null; }
}

function isPrintable(s) {
  if (s === null || s === undefined || s.length === 0) return false;
  let good = 0;
  const n = Math.min(s.length, 160);
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) good++;
  }
  return n > 0 && good / n >= 0.85;
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
  if (hooked.has(k)) return null;
  hooked.add(k);
  return Interceptor.attach(addr, handlers);
}

function moduleDesc(p) {
  try {
    if (typeof Process.findModuleByAddress === 'function') {
      const m = Process.findModuleByAddress(p);
      if (m !== null) return `${m.name}+0x${p.sub(m.base).toString(16)}`;
    }
  } catch (_) {}
  try {
    const r = Process.findRangeByAddress(p);
    if (r !== null) return `${r.protection} ${r.base}-0x${r.base.add(r.size).toString(16)}`;
  } catch (_) {}
  return null;
}

function descPointer(p, dumpLen) {
  const parts = [];
  const m = moduleDesc(p);
  if (m !== null) parts.push(m);

  if (cfg.cstring) {
    const s = safeCString(p, 160);
    if (isPrintable(s)) parts.push(`cstr="${s.replace(/\n/g, '\\n')}"`);
  }

  if (dumpLen > 0) {
    const b = readBytes(p, dumpLen);
    if (b !== null) parts.push(`${dumpLen}B=${bytesToHex(b)}`);
  }

  return parts.length ? ' // ' + parts.join(' | ') : '';
}

function fmtArg(i, p) {
  return `x${i}=${p}${descPointer(p, cfg.hexdump)}`;
}

function fmtRet(p) {
  return `ret=${p}${descPointer(p, cfg.hexdump)}`;
}

function lrDesc(ctx) {
  const lr = ctx.lr;
  const parts = [String(lr)];
  if (currentLoadBias !== null) {
    try {
      const off = lr.sub(currentLoadBias);
      // If it looks inside our unpacked image, show RVA.
      if (off.compare(ptr(0)) >= 0 && off.compare(ptr('0x1000000')) < 0) parts.push(`unpacked+0x${off.toString(16)}`);
    } catch (_) {}
  }
  const m = moduleDesc(lr);
  if (m !== null) parts.push(m);
  return parts.join(' ');
}

function printBacktrace(ctx) {
  try {
    const bt = Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(a => `    ${a} ${DebugSymbol.fromAddress(a)}`)
      .join('\n');
    log(`[bt]\n${bt}`);
  } catch (e) {
    warn(`[bt failed] ${e}`);
  }
}

function installTargetHook(loadBias) {
  if (cfg.rva === null) {
    warn('[target] no offset/rva configured. Use -P \'{"offset":"0x..."}\'');
    return;
  }
  if (targetListener !== null) return;

  const target = loadBias.add(cfg.rva);
  const rvaText = '0x' + cfg.rva.toString(16);
  if (cfg.label === null) cfg.label = `unpacked+${rvaText}`;

  log(`[target] hook ${cfg.label} at ${target} (load_bias=${loadBias} rva=${rvaText}) argc=${cfg.argc} hexdump=${cfg.hexdump}`);

  targetListener = attachOnce(target, `target_${rvaText}`, {
    onEnter(args) {
      if (cfg.maxCalls > 0 && callSeq >= cfg.maxCalls) {
        this.skipLog = true;
        return;
      }

      this.seq = ++callSeq;
      this.skipLog = false;
      this.savedArgs = [];
      for (let i = 0; i < cfg.argc; i++) this.savedArgs.push(args[i]);

      log(`\n[${cfg.label} ENTER #${this.seq}] tid=${this.threadId} caller=${lrDesc(this.context)}`);
      for (let i = 0; i < this.savedArgs.length; i++) log(`  ${fmtArg(i, this.savedArgs[i])}`);
      if (cfg.backtrace) printBacktrace(this.context);
    },
    onLeave(retval) {
      if (this.skipLog) return;
      log(`[${cfg.label} LEAVE #${this.seq}] ${fmtRet(retval)}`);
      if (cfg.maxCalls > 0 && callSeq >= cfg.maxCalls && targetListener !== null) {
        try { targetListener.detach(); log(`[target] detached after maxCalls=${cfg.maxCalls}`); } catch (_) {}
        targetListener = null;
      }
    }
  });
}

function installUnpackedHooks(loadBias) {
  const key = loadBias.toString();
  if (installedUnpackedBases.has(key)) return;
  installedUnpackedBases.add(key);
  currentLoadBias = loadBias;
  installTargetHook(loadBias);
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
      if (cfg.spoofKey && st && st.forcedKey !== null) {
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
      if (cfg.spoofKey && rawKey !== null && forcedKey !== null) {
        log(`[sub_918] forced key=${bytesToHex(forcedKey)}`);
      }
    }
  });

  attachOnce(finalSite, 'sub_918_final_site', {
    onEnter() {
      const st = active918[this.threadId];
      if (cfg.spoofKey && st && st.forcedKey !== null) {
        try { writeBytes(this.context.x0, st.forcedKey); } catch (_) {}
      }
    }
  });

  // sub_167C(dynamic, load_bias, auxv, r_debug); install unpacked hook before hidden init_array runs.
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
  if (started) return;
  started = true;

  if (!configured) warn('[config] rpc init was not called yet; use -P JSON parameters with frida 17');
  if (cfg.rva === null) warn('[config] missing offset/rva; target hook will not be installed');

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

function configure(parameters) {
  let p = parameters || {};
  if (typeof p === 'string') {
    try { p = JSON.parse(p); } catch (_) { p = { offset: p }; }
  }

  const off = p.offset !== undefined ? p.offset : (p.rva !== undefined ? p.rva : p.fn);
  cfg.rva = parsePtrValue(off);
  cfg.argc = parseNum(p.argc !== undefined ? p.argc : (p.args !== undefined ? p.args : p.nargs), cfg.argc);
  cfg.hexdump = parseNum(p.hexdump !== undefined ? p.hexdump : p.dump, cfg.hexdump);
  cfg.cstring = parseBool(p.cstring, cfg.cstring);
  cfg.backtrace = parseBool(p.backtrace, cfg.backtrace);
  cfg.maxCalls = parseNum(p.maxCalls !== undefined ? p.maxCalls : p.max_calls, cfg.maxCalls);
  cfg.spoofKey = parseBool(p.spoof_key !== undefined ? p.spoof_key : p.spoofKey, cfg.spoofKey);
  if (p.label !== undefined && p.label !== null) cfg.label = String(p.label);

  configured = true;
  log(`[config] offset=${cfg.rva} argc=${cfg.argc} hexdump=${cfg.hexdump} cstring=${cfg.cstring} backtrace=${cfg.backtrace} maxCalls=${cfg.maxCalls} spoofKey=${cfg.spoofKey}`);
}

rpc.exports = {
  init(stage, parameters) {
    log(`[rpc.init] stage=${stage} parameters=${JSON.stringify(parameters)}`);
    configure(parameters);
    main();
  },
  hook(rva, options) {
    const p = options || {};
    p.offset = rva;
    configure(p);
    if (currentLoadBias !== null) installTargetHook(currentLoadBias);
    return true;
  }
};

log('[loaded] hook_unpacked_fn_args_ret_frida17.js; pass -P \'{"offset":"0x..."}\'');
