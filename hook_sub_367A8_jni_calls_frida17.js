'use strict';

/*
 * Frida 17.x: hook unpacked libdp sub_367A8 and print JNI calls it makes.
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l hook_sub_367A8_jni_calls_frida17.js
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
const SUB_367A8_START = ptr('0x367a8');
const SUB_367A8_END   = ptr('0x36bc4');

const hooked = new Set();
const installedOuterBases = new Set();
const installedUnpackedBases = new Set();
const installedJniTables = new Set();

let currentLoadBias = null;
let sub367Depth = 0;

const methodMap = {}; // jmethodID -> {kind,name,sig,clazz}
const fieldMap = {};  // jfieldID  -> {kind,name,sig,clazz}
const classMap = {};  // jclass    -> text

function log(s) { console.log(s); }
function warn(s) { console.warn(s); }

function safeCString(p) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
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

function ptrInRange(p, start, end) {
  try { return p.compare(start) >= 0 && p.compare(end) < 0; } catch (_) { return false; }
}

function callerInfo(ctx) {
  if (currentLoadBias === null) return null;
  const lr = ctx.lr;
  const start = currentLoadBias.add(SUB_367A8_START);
  const end = currentLoadBias.add(SUB_367A8_END);
  if (!ptrInRange(lr, start, end)) return null;
  return {
    name: 'sub_367A8',
    lr: lr,
    off: lr.sub(currentLoadBias)
  };
}

function loc(info) {
  return `${info.name}+0x${info.off.sub(SUB_367A8_START).toString(16)} ret=${info.name}_ret@0x${info.off.toString(16)}`;
}

function fmtClass(c) {
  const k = c.toString();
  return classMap[k] ? `${c}(${classMap[k]})` : c.toString();
}

function fmtMethod(id) {
  const k = id.toString();
  const m = methodMap[k];
  if (!m) return id.toString();
  return `${id}(${m.kind} ${m.name} ${m.sig})`;
}

function fmtField(id) {
  const k = id.toString();
  const f = fieldMap[k];
  if (!f) return id.toString();
  return `${id}(${f.kind} ${f.name} ${f.sig})`;
}

function installJniHooks(env) {
  if (env === null || env === undefined || env.isNull()) return;

  let table;
  try { table = env.readPointer(); } catch (e) { warn(`[JNI] cannot read JNIEnv table: ${e}`); return; }

  const tableKey = table.toString();
  if (installedJniTables.has(tableKey)) return;
  installedJniTables.add(tableKey);

  function hookOff(off, name, handlers) {
    let fn;
    try { fn = table.add(off).readPointer(); } catch (e) { warn(`[JNI] read ${name}@${off} failed: ${e}`); return; }
    if (fn.isNull()) return;
    attachOnce(fn, `JNI_${name}`, handlers(fn));
  }

  log(`[JNI] install hooks env=${env} table=${table}`);

  hookOff(0x30, 'FindClass', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.name = safeCString(args[1]);
      log(`[JNI ${loc(this.info)}] FindClass name="${this.name}"`);
    },
    onLeave(retval) {
      if (!this.info) return;
      classMap[retval.toString()] = this.name;
      log(`[JNI ${loc(this.info)}]  -> class=${fmtClass(retval)}`);
    }
  }));

  hookOff(0xf8, 'GetObjectClass', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
      log(`[JNI ${loc(this.info)}] GetObjectClass obj=${this.obj}`);
    },
    onLeave(retval) {
      if (!this.info) return;
      classMap[retval.toString()] = `class_of_${this.obj}`;
      log(`[JNI ${loc(this.info)}]  -> class=${fmtClass(retval)}`);
    }
  }));

  hookOff(0xa8, 'NewGlobalRef', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
      log(`[JNI ${loc(this.info)}] NewGlobalRef obj=${this.obj}`);
    },
    onLeave(retval) {
      if (!this.info) return;
      log(`[JNI ${loc(this.info)}]  -> global=${retval}`);
    }
  }));

  hookOff(0x108, 'GetMethodID', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.name = safeCString(args[2]);
      this.sig = safeCString(args[3]);
      log(`[JNI ${loc(this.info)}] GetMethodID class=${fmtClass(this.clazz)} name="${this.name}" sig="${this.sig}"`);
    },
    onLeave(retval) {
      if (!this.info) return;
      methodMap[retval.toString()] = { kind: 'method', clazz: this.clazz, name: this.name, sig: this.sig };
      log(`[JNI ${loc(this.info)}]  -> methodID=${fmtMethod(retval)}`);
    }
  }));

  hookOff(0x388, 'GetStaticMethodID', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.name = safeCString(args[2]);
      this.sig = safeCString(args[3]);
      log(`[JNI ${loc(this.info)}] GetStaticMethodID class=${fmtClass(this.clazz)} name="${this.name}" sig="${this.sig}"`);
    },
    onLeave(retval) {
      if (!this.info) return;
      methodMap[retval.toString()] = { kind: 'static_method', clazz: this.clazz, name: this.name, sig: this.sig };
      log(`[JNI ${loc(this.info)}]  -> methodID=${fmtMethod(retval)}`);
    }
  }));

  hookOff(0x2f0, 'GetFieldID', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.name = safeCString(args[2]);
      this.sig = safeCString(args[3]);
      log(`[JNI ${loc(this.info)}] GetFieldID class=${fmtClass(this.clazz)} name="${this.name}" sig="${this.sig}"`);
    },
    onLeave(retval) {
      if (!this.info) return;
      fieldMap[retval.toString()] = { kind: 'field', clazz: this.clazz, name: this.name, sig: this.sig };
      log(`[JNI ${loc(this.info)}]  -> fieldID=${fmtField(retval)}`);
    }
  }));

  hookOff(0x480, 'GetStaticFieldID', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.name = safeCString(args[2]);
      this.sig = safeCString(args[3]);
      log(`[JNI ${loc(this.info)}] GetStaticFieldID class=${fmtClass(this.clazz)} name="${this.name}" sig="${this.sig}"`);
    },
    onLeave(retval) {
      if (!this.info) return;
      fieldMap[retval.toString()] = { kind: 'static_field', clazz: this.clazz, name: this.name, sig: this.sig };
      log(`[JNI ${loc(this.info)}]  -> fieldID=${fmtField(retval)}`);
    }
  }));

  hookOff(0x2f8, 'GetObjectField', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
      this.field = args[2];
      log(`[JNI ${loc(this.info)}] GetObjectField obj=${this.obj} field=${fmtField(this.field)}`);
    },
    onLeave(retval) {
      if (!this.info) return;
      log(`[JNI ${loc(this.info)}]  -> obj=${retval}`);
    }
  }));

  hookOff(0x300, 'GetBooleanField', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
      this.field = args[2];
      log(`[JNI ${loc(this.info)}] GetBooleanField obj=${this.obj} field=${fmtField(this.field)}`);
    },
    onLeave(retval) {
      if (!this.info) return;
      log(`[JNI ${loc(this.info)}]  -> bool=${retval.toInt32() & 0xff}`);
    }
  }));

  hookOff(0x340, 'SetObjectField', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      log(`[JNI ${loc(this.info)}] SetObjectField obj=${args[1]} field=${fmtField(args[2])} value=${args[3]}`);
    }
  }));

  hookOff(0x128, 'CallBooleanMethod', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
      this.mid = args[2];
      log(`[JNI ${loc(this.info)}] CallBooleanMethod obj=${this.obj} method=${fmtMethod(this.mid)}`);
    },
    onLeave(retval) {
      if (!this.info) return;
      log(`[JNI ${loc(this.info)}]  -> bool=${retval.toInt32() & 0xff}`);
    }
  }));

  hookOff(0x110, 'CallObjectMethod', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
      this.mid = args[2];
      log(`[JNI ${loc(this.info)}] CallObjectMethod obj=${this.obj} method=${fmtMethod(this.mid)}`);
    },
    onLeave(retval) {
      if (!this.info) return;
      log(`[JNI ${loc(this.info)}]  -> obj=${retval}`);
    }
  }));

  hookOff(0x390, 'CallStaticObjectMethod', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.mid = args[2];
      log(`[JNI ${loc(this.info)}] CallStaticObjectMethod class=${fmtClass(this.clazz)} method=${fmtMethod(this.mid)}`);
    },
    onLeave(retval) {
      if (!this.info) return;
      log(`[JNI ${loc(this.info)}]  -> obj=${retval}`);
    }
  }));

  hookOff(0x538, 'NewStringUTF', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.s = safeCString(args[1]);
      log(`[JNI ${loc(this.info)}] NewStringUTF "${this.s}"`);
    },
    onLeave(retval) {
      if (!this.info) return;
      log(`[JNI ${loc(this.info)}]  -> jstring=${retval}`);
    }
  }));

  hookOff(0x720, 'ExceptionCheck', () => ({
    onEnter() { this.info = callerInfo(this.context); },
    onLeave(retval) {
      if (!this.info) return;
      const v = retval.toInt32() & 0xff;
      if (v !== 0) log(`[JNI ${loc(this.info)}] ExceptionCheck -> ${v}`);
    }
  }));
}

function installUnpackedHooks(loadBias) {
  const key = loadBias.toString();
  if (installedUnpackedBases.has(key)) return;
  installedUnpackedBases.add(key);
  currentLoadBias = loadBias;

  const sub367 = loadBias.add(SUB_367A8_START);
  log(`[unpacked] load_bias=${loadBias} hook sub_367A8=${sub367}`);

  attachOnce(sub367, 'sub_367A8_entry_leave', {
    onEnter(args) {
      sub367Depth++;
      this.env = args[0];
      installJniHooks(this.env);
      log(`[sub_367A8 enter] env=${this.env}`);
    },
    onLeave(retval) {
      log(`[sub_367A8 leave] ret=${retval} depth=${sub367Depth}`);
      sub367Depth--;
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
      if (rawKey !== null && forcedKey !== null) {
        log(`[sub_918] raw=${bytesToHex(rawKey)} forced=${bytesToHex(forcedKey)}`);
      }
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

  // sub_167C(dynamic, load_bias, auxv, r_debug); load_bias is enough to hook unpacked sub_367A8.
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
