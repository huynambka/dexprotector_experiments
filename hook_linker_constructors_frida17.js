'use strict';

/*
 * Frida 17.x: hook Android linker's constructor path.
 *
 * Run early (spawn) or you will miss .init_array:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l hook_linker_constructors_frida17.js
 *
 * This hooks, when symbols are available in linker/linker64:
 *   - soinfo::call_constructors()
 *   - call_array(... DT_INIT_ARRAY ...)
 *   - call_function(... DT_INIT / DT_INIT_ARRAY ...)
 *
 * For current sample, libdexprotector.so .init_array[0] is RVA 0x378.
 */

const TARGET_LIB = 'libdexprotector.so';
const TARGET_INIT_RVA = ptr('0x378');
const DP_SUB_25B8_RVA = ptr('0x25b8');
const DP_SUB_25B8_KEY_RVA = ptr('0x2d7');
const PRINT_ALL = false;        // false: focus on target lib + constructor calls
const PRINT_BACKTRACE = false;

const hookedFns = new Set();
const installedDexprotectorBases = new Set();
let depth = 0;

function log(s) { console.log(s); }
function warn(s) { console.warn(s); }

function safeCString(p) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    return p.readCString();
  } catch (_) {
    return null;
  }
}

function ptrNum(p) {
  try { return parseInt(p.toString(), 16); } catch (_) { return 0; }
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

function describeAddress(p) {
  if (p === null || p === undefined || p.isNull()) return String(p);
  const m = Process.findModuleByAddress(p);
  if (m === null) return p.toString();
  return `${p} ${m.name}+0x${p.sub(m.base).toString(16)} ${m.path}`;
}

function isTargetPath(s) {
  return s !== null && s.indexOf(TARGET_LIB) !== -1;
}

function backtrace(ctx) {
  if (!PRINT_BACKTRACE) return;
  try {
    log(Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
  } catch (e) {
    warn('backtrace failed: ' + e);
  }
}

function attachOnce(fn, label) {
  const k = fn.toString();
  if (hookedFns.has(k)) return;
  hookedFns.add(k);
  Interceptor.attach(fn, {
    onEnter(args) {
      log(`[ENTER target ctor] ${label} ${describeAddress(fn)}`);
      backtrace(this.context);
    },
    onLeave(retval) {
      log(`[LEAVE target ctor] ${label}`);
    }
  });
  log(`[hooked target ctor] ${label} @ ${describeAddress(fn)}`);
}

function u32(x) {
  return x >>> 0;
}

function readU32Array(p, count) {
  const out = [];
  for (let i = 0; i < count; i++) out.push(p.add(i * 4).readU32() >>> 0);
  return out;
}

function bytesToHex(bytes) {
  return bytes.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

function bytesToEscapedString(bytes) {
  let end = bytes.indexOf(0);
  if (end === -1) end = bytes.length;
  const s = [];
  for (let i = 0; i < end; i++) {
    const b = bytes[i] & 0xff;
    if (b >= 0x20 && b <= 0x7e && b !== 0x5c) {
      s.push(String.fromCharCode(b));
    } else if (b === 0x5c) {
      s.push('\\\\');
    } else if (b === 0x0a) {
      s.push('\\n');
    } else if (b === 0x0d) {
      s.push('\\r');
    } else if (b === 0x09) {
      s.push('\\t');
    } else {
      s.push('\\x' + ('0' + b.toString(16)).slice(-2));
    }
  }
  return s.join('');
}

/*
 * JS implementation of libdexprotector.so:sub_25B8().
 *
 * Native prototype observed:
 *   x0 = encrypted blob pointer
 *   x1 = output buffer
 *   x2 = plaintext length
 *
 * Blob layout:
 *   blob[0:8] = per-blob seed, loaded as w9/w14
 *   blob[8:]  = ciphertext
 *
 * Static table/key:
 *   libdexprotector.so + 0x2d7, 8 little-endian u32 words
 */
function dpSub25B8(blobPtr, len, keyTable) {
  len = Number(len);
  if (len <= 0) return [];

  let w9 = blobPtr.readU32() >>> 0;
  let w14 = blobPtr.add(4).readU32() >>> 0;
  const cipher = blobPtr.add(8);
  const out = [];
  let ks = [0, 0, 0, 0, 0, 0, 0, 0];

  for (let i = 0; i < len; i++) {
    if ((i & 7) === 0) {
      let w0 = 0xfffffffe >>> 0;
      let w16 = 0xfffffffd >>> 0;
      let w17 = 0, w3 = 0, w4 = 0, w5 = 0;

      while (true) {
        w17 = u32(w0 + 2);
        w0 = u32(w0 + 3);

        const idx3 = w17 & 6;
        const idx0 = w0 & 7;

        w4 = u32(w9 << 6);
        w16 = u32(w16 + 4);
        w5 = u32(w4 ^ (w9 >>> 8));

        const keepGoing = (w17 >>> 0) < 0x3e;

        w3 = keyTable[idx3] >>> 0;
        w4 = u32(w9 + w5);

        let wt = keyTable[idx0] >>> 0;
        w3 = u32(w14 + w3);
        w14 = u32(w17 + w4);
        w14 = u32(w14 + w3);
        wt = u32(wt + w5);

        let w6 = u32(w14 << 6);
        wt = u32(w3 + wt);
        w5 = u32(w6 ^ (w14 >>> 8));
        wt = u32(wt + w5);
        w5 = u32(wt + u32(w9 << 1));

        w0 = w17;
        w9 = u32(w16 + w5);

        if (!keepGoing) break;
      }

      w9 = u32(w5 + w16);

      const oldW14 = w14;
      const outW9 = w9;
      const outW14 = u32(w3 + u32(w4 + w17));

      ks = [
        outW9 & 0xff,
        (outW9 >>> 8) & 0xff,
        (outW9 >>> 16) & 0xff,
        (outW9 >>> 24) & 0xff,
        outW14 & 0xff,
        (oldW14 >>> 8) & 0xff,
        (outW14 >>> 16) & 0xff,
        (outW14 >>> 24) & 0xff,
      ];
    }

    out.push((cipher.add(i).readU8() ^ ks[i & 7]) & 0xff);
  }

  return out;
}

function findTargetModule(path) {
  let m = Process.findModuleByName(TARGET_LIB);
  if (m !== null) return m;
  const mods = Process.enumerateModules();
  return mods.find(x => x.path === path || x.path.indexOf(TARGET_LIB) !== -1 || x.name === TARGET_LIB) || null;
}

function installDexprotectorHooks(path) {
  const m = findTargetModule(path);
  if (m === null) {
    warn(`[${TARGET_LIB}] module not visible yet while handling ${path}`);
    return;
  }

  const baseKey = m.base.toString();
  if (installedDexprotectorBases.has(baseKey)) return;
  installedDexprotectorBases.add(baseKey);

  const keyPtr = m.base.add(DP_SUB_25B8_KEY_RVA);
  const keyTable = readU32Array(keyPtr, 8);
  const keyBytes = [];
  keyTable.forEach(w => {
    keyBytes.push(w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, (w >>> 24) & 0xff);
  });

  log(`[${TARGET_LIB}] base=${m.base} path=${m.path}`);
  log(`[sub_25B8 key] ${TARGET_LIB}+${DP_SUB_25B8_KEY_RVA} bytes=${bytesToHex(keyBytes)}`);
  log(`[sub_25B8 key] u32_le={ ${keyTable.map(w => '0x' + w.toString(16).padStart(8, '0')).join(', ')} }`);

  attachOnce(m.base.add(TARGET_INIT_RVA), `${TARGET_LIB}+${TARGET_INIT_RVA}`);

  const decFn = m.base.add(DP_SUB_25B8_RVA);
  Interceptor.attach(decFn, {
    onEnter(args) {
      this.enc = args[0];
      this.out = args[1];
      this.len = ptrNum(args[2]);
      this.preview = null;
      this.err = null;

      const enc = this.enc;
      const len = this.len;
      if (len <= 0 || len > 0x10000) {
        this.err = `ignored len=${len}`;
        return;
      }
      try {
        this.preview = dpSub25B8(enc, len, keyTable);
      } catch (e) {
        this.err = String(e);
      }
    },
    onLeave(retval) {
      let line = `[sub_25B8 ret] retval=${retval} enc=${describeAddress(this.enc)} out=${this.out} len=0x${this.len.toString(16)}`;

      if (this.preview !== null) {
        line += ` -> "${bytesToEscapedString(this.preview)}" hex=${bytesToHex(this.preview)}`;
      } else if (this.err !== null) {
        line += ` err=${this.err}`;
      }

      // sub_25B8 returns x1/out. Print actual return pointer, and if possible
      // read the real bytes written by the native function from retval.
      if (!retval.isNull() && this.len > 0 && this.len <= 0x10000) {
        try {
          const actual = Array.from(retval.readByteArray(this.len));
          line += ` actual="${bytesToEscapedString(actual)}" actual_hex=${bytesToHex(actual)}`;
        } catch (e) {
          line += ` actual_read_err=${e}`;
        }
      }

      log(line);
    }
  });
  log(`[hooked sub_25B8] ${describeAddress(decFn)}`);
}

function main() {
  const linker = findLinkerModule();
  if (linker === undefined || linker === null) {
    warn('linker/linker64 module not found');
    return;
  }

  log(`[linker] ${linker.name} base=${linker.base} path=${linker.path}`);

  let syms = [];
  try {
    syms = enumSymbols(linker);
    log(`[linker] symbols=${syms.length}`);
  } catch (e) {
    warn('Could not enumerate linker symbols: ' + e);
    return;
  }

  const getRealpathSym = syms.find(s => s.type === 'function' && s.name.indexOf('soinfo') !== -1 && s.name.indexOf('get_realpath') !== -1);
  const getSonameSym = syms.find(s => s.type === 'function' && s.name.indexOf('soinfo') !== -1 && s.name.indexOf('get_soname') !== -1);
  const getRealpath = getRealpathSym ? new NativeFunction(getRealpathSym.address, 'pointer', ['pointer']) : null;
  const getSoname = getSonameSym ? new NativeFunction(getSonameSym.address, 'pointer', ['pointer']) : null;

  if (getRealpathSym) log(`[hook helper] ${getRealpathSym.name} @ ${getRealpathSym.address}`);
  if (getSonameSym) log(`[hook helper] ${getSonameSym.name} @ ${getSonameSym.address}`);

  function soinfoPath(si) {
    for (const f of [getRealpath, getSoname]) {
      if (f === null) continue;
      try {
        const p = f(si);
        const s = safeCString(p);
        if (s) return s;
      } catch (_) {}
    }
    return `<soinfo ${si}>`;
  }

  // soinfo::call_constructors() -- member fn, x0 == soinfo* on arm64.
  const ctorSyms = syms.filter(s => s.type === 'function' &&
    s.name.indexOf('call_constructors') !== -1 &&
    s.name.indexOf('call_pre_init') === -1 &&
    s.name.indexOf('call_destructors') === -1);

  ctorSyms.forEach(s => {
    log(`[hook] call_constructors candidate ${s.name} @ ${s.address}`);
    Interceptor.attach(s.address, {
      onEnter(args) {
        this.si = args[0];
        this.path = soinfoPath(this.si);
        this.d = depth++;
        if (PRINT_ALL || isTargetPath(this.path)) {
          log(`${'  '.repeat(this.d)}[call_constructors ENTER] soinfo=${this.si} path=${this.path}`);
          if (isTargetPath(this.path)) installDexprotectorHooks(this.path);
          backtrace(this.context);
        }
      },
      onLeave(retval) {
        depth--;
        if (PRINT_ALL || isTargetPath(this.path)) {
          log(`${'  '.repeat(this.d)}[call_constructors LEAVE] path=${this.path}`);
        }
      }
    });
  });

  if (ctorSyms.length === 0 && arraySyms.length === 0 && fnSyms.length === 0) {
    warn('No linker constructor symbols found. Device linker may be stripped; locate offsets for this linker build with r2/IDA and attach by linker.base.add(offset).');
  }
}

setImmediate(main);
