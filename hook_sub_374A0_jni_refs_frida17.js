'use strict';

/*
 * Frida 17.x: hook unpacked libdp sub_374A0 and list Java classes/methods/fields
 * plus globals saved by the protector.
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l hook_sub_374A0_jni_refs_frida17.js
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
const SUB_374A0_START = ptr('0x374a0');
const SUB_374A0_END   = ptr('0x37be4');
const SUB_37BE4_START = ptr('0x37be4');
const SUB_37BE4_END   = ptr('0x37d08');

// Store-sites inside sub_374A0: STR X0, [global].
const GLOBAL_STORES = [
  { site: ptr('0x37524'), data: ptr('0x8ca30'), name: 'qword_8CA30', what: 'global ref from FindClass result' },
  { site: ptr('0x375f8'), data: ptr('0x8c9f8'), name: 'qword_8C9F8', what: 'global ref from CallStaticObjectMethod result' },
  { site: ptr('0x376cc'), data: ptr('0x8ca18'), name: 'qword_8CA18', what: 'global ref from GetObjectField result' },
  { site: ptr('0x378a0'), data: ptr('0x8ca48'), name: 'qword_8CA48', what: 'global ref from nested GetObjectField result' },
  { site: ptr('0x379ec'), data: ptr('0x8ca40'), name: 'qword_8CA40', what: 'global ref from CallObjectMethod result' },
  { site: ptr('0x37ab8'), data: ptr('0x8ca08'), name: 'qword_8CA08', what: 'global ref from GetStaticObjectField result' },
  { site: ptr('0x37b04'), data: ptr('0x8ca50'), name: 'qword_8CA50', what: 'native C string copied by sub_37BE4 #1' },
  { site: ptr('0x37b50'), data: ptr('0x8ca10'), name: 'qword_8CA10', what: 'native C string copied by sub_37BE4 #2' },
  { site: ptr('0x37b9c'), data: ptr('0x8ca58'), name: 'qword_8CA58', what: 'native C string copied by sub_37BE4 #3' },
];

const hooked = new Set();
const installedOuterBases = new Set();
const installedUnpackedBases = new Set();
const installedJniTables = new Set();

let currentLoadBias = null;

// Track JNI handles seen by this script.
const methodMap = {}; // jmethodID -> {kind,name,sig,clazz}
const fieldMap = {};  // jfieldID  -> {kind,name,sig,clazz}
const classMap = {};  // jclass    -> text
const handleInfo = {}; // jobject/jclass/jstring/global ref -> text

// Per-thread sub_374A0 sessions.
const sessions = {}; // tid -> {depth, events, saves, helperCalls}

function log(s) { console.log(s); }
function warn(s) { console.warn(s); }

function safeCString(p) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    return p.readCString();
  } catch (_) { return null; }
}

function safePrintableCString(p) {
  const s = safeCString(p);
  if (s === null) return null;
  if (s.length === 0) return '';
  // Avoid dumping random binary if p is actually a jobject/jclass handle.
  let good = 0;
  const max = Math.min(s.length, 120);
  for (let i = 0; i < max; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) good++;
  }
  if (max > 0 && good / max < 0.85) return null;
  return s.length > 160 ? s.slice(0, 160) + '...' : s;
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

function offOf(addr) {
  if (currentLoadBias === null) return null;
  try { return addr.sub(currentLoadBias); } catch (_) { return null; }
}

function callerInfo(ctx) {
  if (currentLoadBias === null) return null;
  const lr = ctx.lr;
  const sub374Start = currentLoadBias.add(SUB_374A0_START);
  const sub374End = currentLoadBias.add(SUB_374A0_END);
  const helperStart = currentLoadBias.add(SUB_37BE4_START);
  const helperEnd = currentLoadBias.add(SUB_37BE4_END);

  if (ptrInRange(lr, sub374Start, sub374End)) {
    const off = offOf(lr);
    return { name: 'sub_374A0', start: SUB_374A0_START, off: off };
  }
  if (ptrInRange(lr, helperStart, helperEnd)) {
    const off = offOf(lr);
    return { name: 'sub_37BE4', start: SUB_37BE4_START, off: off };
  }
  return null;
}

function loc(info) {
  return `${info.name}+0x${info.off.sub(info.start).toString(16)} ret@0x${info.off.toString(16)}`;
}

function getSession(tid) {
  return sessions[tid] || null;
}

function record(tid, line, kind) {
  const s = getSession(tid);
  if (s !== null) {
    if (kind === 'save') s.saves.push(line);
    else if (kind === 'helper') s.helperCalls.push(line);
    else s.events.push(line);
  }
}

function fmtClass(c) {
  const k = c.toString();
  if (classMap[k]) return `${c}(${classMap[k]})`;
  if (handleInfo[k]) return `${c}(${handleInfo[k]})`;
  return c.toString();
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

function describeHandle(p) {
  if (p === null || p === undefined) return '';
  const k = p.toString();
  const parts = [];
  if (handleInfo[k]) parts.push(handleInfo[k]);
  if (classMap[k]) parts.push(`jclass ${classMap[k]}`);
  if (methodMap[k]) parts.push(`${methodMap[k].kind} ${methodMap[k].name} ${methodMap[k].sig}`);
  if (fieldMap[k]) parts.push(`${fieldMap[k].kind} ${fieldMap[k].name} ${fieldMap[k].sig}`);
  const cs = safePrintableCString(p);
  if (cs !== null) parts.push(`cstr="${cs}"`);
  return parts.length ? ` // ${parts.join(' | ')}` : '';
}

function rememberHandle(p, desc) {
  try {
    if (p === null || p === undefined || p.isNull()) return;
    handleInfo[p.toString()] = desc;
  } catch (_) {}
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
    },
    onLeave(retval) {
      if (!this.info) return;
      if (!retval.isNull()) {
        classMap[retval.toString()] = this.name;
        rememberHandle(retval, `local jclass ${this.name}`);
      }
      const line = `[LOOKUP ${loc(this.info)}] FindClass "${this.name}" -> ${fmtClass(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0xf8, 'GetObjectClass', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
    },
    onLeave(retval) {
      if (!this.info) return;
      if (!retval.isNull()) {
        const src = handleInfo[this.obj.toString()] || this.obj.toString();
        classMap[retval.toString()] = `class_of_${src}`;
        rememberHandle(retval, `local jclass class_of_${src}`);
      }
      const line = `[LOOKUP ${loc(this.info)}] GetObjectClass obj=${this.obj}${describeHandle(this.obj)} -> ${fmtClass(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0xa8, 'NewGlobalRef', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
    },
    onLeave(retval) {
      if (!this.info) return;
      const srcDesc = handleInfo[this.obj.toString()] || classMap[this.obj.toString()] || this.obj.toString();
      if (!retval.isNull()) rememberHandle(retval, `global ref to ${srcDesc}`);
      const line = `[SAVE? ${loc(this.info)}] NewGlobalRef obj=${this.obj}${describeHandle(this.obj)} -> ${retval}${describeHandle(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0xb8, 'DeleteLocalRef', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      const line = `[JNI ${loc(this.info)}] DeleteLocalRef obj=${args[1]}${describeHandle(args[1])}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x108, 'GetMethodID', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.name = safeCString(args[2]);
      this.sig = safeCString(args[3]);
    },
    onLeave(retval) {
      if (!this.info) return;
      if (!retval.isNull()) methodMap[retval.toString()] = { kind: 'method', clazz: this.clazz, name: this.name, sig: this.sig };
      const line = `[LOOKUP ${loc(this.info)}] GetMethodID class=${fmtClass(this.clazz)} name="${this.name}" sig="${this.sig}" -> ${fmtMethod(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x388, 'GetStaticMethodID', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.name = safeCString(args[2]);
      this.sig = safeCString(args[3]);
    },
    onLeave(retval) {
      if (!this.info) return;
      if (!retval.isNull()) methodMap[retval.toString()] = { kind: 'static_method', clazz: this.clazz, name: this.name, sig: this.sig };
      const line = `[LOOKUP ${loc(this.info)}] GetStaticMethodID class=${fmtClass(this.clazz)} name="${this.name}" sig="${this.sig}" -> ${fmtMethod(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x2f0, 'GetFieldID', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.name = safeCString(args[2]);
      this.sig = safeCString(args[3]);
    },
    onLeave(retval) {
      if (!this.info) return;
      if (!retval.isNull()) fieldMap[retval.toString()] = { kind: 'field', clazz: this.clazz, name: this.name, sig: this.sig };
      const line = `[LOOKUP ${loc(this.info)}] GetFieldID class=${fmtClass(this.clazz)} name="${this.name}" sig="${this.sig}" -> ${fmtField(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x480, 'GetStaticFieldID', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.name = safeCString(args[2]);
      this.sig = safeCString(args[3]);
    },
    onLeave(retval) {
      if (!this.info) return;
      if (!retval.isNull()) fieldMap[retval.toString()] = { kind: 'static_field', clazz: this.clazz, name: this.name, sig: this.sig };
      const line = `[LOOKUP ${loc(this.info)}] GetStaticFieldID class=${fmtClass(this.clazz)} name="${this.name}" sig="${this.sig}" -> ${fmtField(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x2f8, 'GetObjectField', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
      this.field = args[2];
    },
    onLeave(retval) {
      if (!this.info) return;
      const desc = `object field ${fmtField(this.field)} from ${this.obj}`;
      if (!retval.isNull()) rememberHandle(retval, desc);
      const line = `[CALL ${loc(this.info)}] GetObjectField obj=${this.obj}${describeHandle(this.obj)} field=${fmtField(this.field)} -> ${retval}${describeHandle(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x488, 'GetStaticObjectField', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.field = args[2];
    },
    onLeave(retval) {
      if (!this.info) return;
      const desc = `static object field ${fmtField(this.field)} from ${fmtClass(this.clazz)}`;
      if (!retval.isNull()) rememberHandle(retval, desc);
      const line = `[CALL ${loc(this.info)}] GetStaticObjectField class=${fmtClass(this.clazz)} field=${fmtField(this.field)} -> ${retval}${describeHandle(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x110, 'CallObjectMethod', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.obj = args[1];
      this.mid = args[2];
    },
    onLeave(retval) {
      if (!this.info) return;
      const desc = `return of ${fmtMethod(this.mid)} on ${this.obj}`;
      if (!retval.isNull()) rememberHandle(retval, desc);
      const line = `[CALL ${loc(this.info)}] CallObjectMethod obj=${this.obj}${describeHandle(this.obj)} method=${fmtMethod(this.mid)} -> ${retval}${describeHandle(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x390, 'CallStaticObjectMethod', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.clazz = args[1];
      this.mid = args[2];
    },
    onLeave(retval) {
      if (!this.info) return;
      const desc = `return of ${fmtMethod(this.mid)} on ${fmtClass(this.clazz)}`;
      if (!retval.isNull()) rememberHandle(retval, desc);
      const line = `[CALL ${loc(this.info)}] CallStaticObjectMethod class=${fmtClass(this.clazz)} method=${fmtMethod(this.mid)} -> ${retval}${describeHandle(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x538, 'NewStringUTF', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.s = safeCString(args[1]);
    },
    onLeave(retval) {
      if (!this.info) return;
      if (!retval.isNull()) rememberHandle(retval, `jstring "${this.s}"`);
      const line = `[CALL ${loc(this.info)}] NewStringUTF "${this.s}" -> ${retval}${describeHandle(retval)}`;
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x548, 'GetStringUTFChars', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      this.jstr = args[1];
    },
    onLeave(retval) {
      if (!this.info) return;
      const s = safePrintableCString(retval);
      const line = `[CALL ${loc(this.info)}] GetStringUTFChars jstr=${this.jstr}${describeHandle(this.jstr)} -> ${retval}` + (s !== null ? ` "${s}"` : '');
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x550, 'ReleaseStringUTFChars', () => ({
    onEnter(args) {
      this.info = callerInfo(this.context);
      if (!this.info) return;
      const s = safePrintableCString(args[2]);
      const line = `[JNI ${loc(this.info)}] ReleaseStringUTFChars jstr=${args[1]} chars=${args[2]}` + (s !== null ? ` "${s}"` : '');
      log(line); record(this.threadId, line);
    }
  }));

  hookOff(0x720, 'ExceptionCheck', () => ({
    onEnter() { this.info = callerInfo(this.context); },
    onLeave(retval) {
      if (!this.info) return;
      const v = retval.toInt32() & 0xff;
      if (v !== 0) {
        const line = `[JNI ${loc(this.info)}] ExceptionCheck -> ${v}`;
        log(line); record(this.threadId, line);
      }
    }
  }));
}

function dumpFinalGlobals(loadBias, tid) {
  log('--- sub_374A0 final globals ---');
  for (const g of GLOBAL_STORES) {
    const addr = loadBias.add(g.data);
    let val = ptr(0);
    try { val = addr.readPointer(); } catch (_) {}
    const line = `[GLOBAL] ${g.name}@+0x${g.data.toString(16)} = ${val}${describeHandle(val)}  // ${g.what}`;
    log(line); record(tid, line, 'save');
  }
}

function installUnpackedHooks(loadBias) {
  const key = loadBias.toString();
  if (installedUnpackedBases.has(key)) return;
  installedUnpackedBases.add(key);
  currentLoadBias = loadBias;

  const sub374 = loadBias.add(SUB_374A0_START);
  const helper = loadBias.add(SUB_37BE4_START);
  log(`[unpacked] load_bias=${loadBias} hook sub_374A0=${sub374} sub_37BE4=${helper}`);

  attachOnce(sub374, 'sub_374A0_entry_leave', {
    onEnter(args) {
      const tid = this.threadId;
      if (!sessions[tid]) sessions[tid] = { depth: 0, events: [], saves: [], helperCalls: [] };
      sessions[tid].depth++;
      this.tid = tid;
      this.env = args[0];
      installJniHooks(this.env);
      log(`\n[sub_374A0 enter] env=${this.env} load_bias=${currentLoadBias}`);
    },
    onLeave(retval) {
      const tid = this.tid;
      log(`[sub_374A0 leave] ret=${retval}`);
      dumpFinalGlobals(currentLoadBias, tid);
      const s = sessions[tid];
      if (s) {
        log(`--- summary: ${s.events.length} JNI events, ${s.saves.length} saves, ${s.helperCalls.length} helper calls ---`);
      }
      if (s) {
        s.depth--;
        if (s.depth <= 0) delete sessions[tid];
      }
      log('--- end sub_374A0 ---\n');
    }
  });

  attachOnce(helper, 'sub_37BE4_entry_leave', {
    onEnter(args) {
      const lr = this.context.lr;
      const sub374Start = currentLoadBias.add(SUB_374A0_START);
      const sub374End = currentLoadBias.add(SUB_374A0_END);
      this.fromSub374 = ptrInRange(lr, sub374Start, sub374End) || getSession(this.threadId) !== null;
      if (!this.fromSub374) return;
      this.fieldName = safeCString(args[3]);
      this.env = args[0];
      this.clazz = args[1];
      this.obj = args[2];
      const line = `[HELPER sub_37BE4 enter] class=${fmtClass(this.clazz)} obj=${this.obj}${describeHandle(this.obj)} fieldName="${this.fieldName}"`;
      log(line); record(this.threadId, line, 'helper');
    },
    onLeave(retval) {
      if (!this.fromSub374) return;
      const s = safePrintableCString(retval);
      if (!retval.isNull()) rememberHandle(retval, `native copy for field "${this.fieldName}"` + (s !== null ? ` = "${s}"` : ''));
      const line = `[HELPER sub_37BE4 leave] fieldName="${this.fieldName}" -> ${retval}` + (s !== null ? ` "${s}"` : '');
      log(line); record(this.threadId, line, 'helper');
    }
  });

  for (const g of GLOBAL_STORES) {
    attachOnce(loadBias.add(g.site), `store_${g.name}`, {
      onEnter() {
        const val = this.context.x0;
        const line = `[SAVE ${loc({ name: 'sub_374A0', start: SUB_374A0_START, off: g.site })}] ${g.name} <- ${val}${describeHandle(val)}  // ${g.what}`;
        log(line); record(this.threadId, line, 'save');
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
