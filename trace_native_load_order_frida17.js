'use strict';

/*
 * Frida 17.x Android native library load-order tracer
 * Target package: com.dexprotector.detector.envchecks
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l trace_native_load_order_frida17.js
 *
 * Notes:
 * - Spawn with -f to catch early loads. Frida 17 resumes by default after the script is loaded.
 * - Set SHOW_ONLY_APP_RELATED=true below if you only want app/package-related .so lines.
 */

const TARGET_PKG = 'com.dexprotector.detector.envchecks';

// Known native libs in the provided split_config.arm64_v8a.apk. Keep this list even
// when the linker is called with only "libfoo.so" and no full app path.
const APP_LIB_BASENAMES = new Set([
  'libalice.so',
  'libdatastore_shared_counter.so',
  'libdexprotector.so',
  'libenvchecks.so',
]);

const SHOW_ONLY_APP_RELATED = true; // true => suppress unrelated framework/system libs
const PRINT_JAVA_REQUESTS = true;    // System.load/loadLibrary and Runtime.* requests
const PRINT_STACKS = false;          // true => print Java/native call stacks for each request

let callSeq = 0;       // every Java/native loader call
let loadedSeq = 0;     // confirmed newly mapped modules
const startMs = Date.now();
let knownModules = new Set();
const observedLoads = [];

function ts() {
  const ms = Date.now() - startMs;
  return (ms / 1000).toFixed(3).padStart(8, ' ');
}

function log(line) {
  console.log(`${ts()} ${line}`);
}

function warn(line) {
  console.warn(`${ts()} ${line}`);
}

function basename(path) {
  if (path === null || path === undefined) return '<null>';
  const s = String(path);
  const bang = s.lastIndexOf('!');
  const slash = s.lastIndexOf('/');
  const cut = Math.max(bang, slash);
  return cut >= 0 ? s.substring(cut + 1) : s;
}

function safeCString(p) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    return p.readCString();
  } catch (e) {
    return `<readCString failed: ${e}>`;
  }
}

function ptrToHex(p) {
  try { return p.toString(); } catch (_) { return String(p); }
}

function moduleKey(m) {
  return `${m.base}|${m.path}`;
}

function snapshotModuleKeys() {
  const keys = new Set();
  Process.enumerateModules().forEach(m => keys.add(moduleKey(m)));
  return keys;
}

function isAppRelatedPath(path) {
  if (path === null || path === undefined) return false;
  const s = String(path);
  const b = basename(s);
  return s.indexOf(TARGET_PKG) !== -1 ||
         s.indexOf(`/data/data/${TARGET_PKG}/`) !== -1 ||
         s.indexOf(`/data/user/0/${TARGET_PKG}/`) !== -1 ||
         s.indexOf(`/data/user_de/0/${TARGET_PKG}/`) !== -1 ||
         APP_LIB_BASENAMES.has(b);
}

function shouldPrintPath(path) {
  return !SHOW_ONLY_APP_RELATED || isAppRelatedPath(path);
}

function moduleLabel(m) {
  const app = isAppRelatedPath(m.path) || APP_LIB_BASENAMES.has(m.name) ? ' APP' : '';
  return `${m.name}${app} base=${m.base} size=0x${m.size.toString(16)} path=${m.path}`;
}

function newModulesSince(beforeKeys) {
  const out = [];
  Process.enumerateModules().forEach(m => {
    const k = moduleKey(m);
    if (!beforeKeys.has(k) && !knownModules.has(k)) out.push(m);
  });
  return out;
}

function rememberAllModules() {
  knownModules = snapshotModuleKeys();
}

function findBestModuleForLoadPath(path) {
  if (path === null || path === undefined) return null;
  const b = basename(path);
  let best = null;
  Process.enumerateModules().forEach(m => {
    if (m.path === path || m.name === b || basename(m.path) === b) {
      if (best === null || m.path === path) best = m;
    }
  });
  return best;
}

function printInitialSnapshot() {
  const mods = Process.enumerateModules();
  let printed = 0;
  log(`=== initial module snapshot for pid=${Process.id} arch=${Process.arch} platform=${Process.platform} ===`);
  mods.forEach(m => {
    if (shouldPrintPath(m.path)) {
      printed++;
      log(`[PRE ${printed.toString().padStart(2, '0')}] ${moduleLabel(m)}`);
    }
  });
  if (printed === 0) log('[PRE --] no package/app-related modules were already loaded');
  log('=== live load hooks armed ===');
}

function printNativeBacktrace(context) {
  if (!PRINT_STACKS) return;
  try {
    const bt = Thread.backtrace(context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .join('\n        ');
    log(`        native backtrace:\n        ${bt}`);
  } catch (e) {
    warn(`        native backtrace failed: ${e}`);
  }
}

function printJavaBacktrace() {
  if (!PRINT_STACKS || !Java.available) return;
  try {
    Java.performNow(() => {
      const Log = Java.use('android.util.Log');
      const Exception = Java.use('java.lang.Exception');
      log('        Java stack:\n' + Log.getStackTraceString(Exception.$new()));
    });
  } catch (e) {
    warn(`        Java stack failed: ${e}`);
  }
}

function recordLoadedModule(m, via, requestedPath) {
  const key = moduleKey(m);
  knownModules.add(key);
  loadedSeq++;
  observedLoads.push({
    n: loadedSeq,
    via: via,
    requestedPath: requestedPath,
    name: m.name,
    base: m.base.toString(),
    size: m.size,
    path: m.path,
    app: isAppRelatedPath(m.path) || APP_LIB_BASENAMES.has(m.name),
  });
  if (shouldPrintPath(m.path) || shouldPrintPath(requestedPath)) {
    log(`[LOAD ${loadedSeq.toString().padStart(2, '0')}] via=${via} requested=${requestedPath} -> ${moduleLabel(m)}`);
  }
}

function hookNativeLoaderExport(name) {
  const addr = Module.findGlobalExportByName(name);
  if (addr === null) {
    warn(`[hook] ${name} not found`);
    return;
  }

  Interceptor.attach(addr, {
    onEnter(args) {
      this.api = name;
      this.seq = ++callSeq;
      this.path = safeCString(args[0]);
      this.flags = args[1];
      this.before = snapshotModuleKeys();

      if (shouldPrintPath(this.path)) {
        log(`[CALL ${this.seq.toString().padStart(3, '0')}] ${name}(path=${this.path}, flags=${ptrToHex(this.flags)})`);
        printNativeBacktrace(this.context);
      }
    },
    onLeave(retval) {
      const ok = !retval.isNull();
      const interesting = shouldPrintPath(this.path);
      if (interesting) {
        log(`[RET  ${this.seq.toString().padStart(3, '0')}] ${this.api}(path=${this.path}) => ${retval}${ok ? '' : ' FAIL'}`);
      }

      if (!ok) return;

      const newlyMapped = newModulesSince(this.before);
      if (newlyMapped.length > 0) {
        newlyMapped.forEach(m => recordLoadedModule(m, this.api, this.path));
        return;
      }

      // dlopen() of an already-loaded lib still succeeds and returns a handle.
      // Keep this visible for app libs because it tells us the request order.
      const m = findBestModuleForLoadPath(this.path);
      if (m !== null && (shouldPrintPath(this.path) || shouldPrintPath(m.path))) {
        log(`[HIT  ${this.seq.toString().padStart(3, '0')}] via=${this.api} already-loaded -> ${moduleLabel(m)}`);
      }
    }
  });

  log(`[hook] ${name} @ ${addr}`);
}

function hookNativeLoaders() {
  // android_dlopen_ext is what Android's NativeLoader/linker normally uses.
  // dlopen is still used by many apps/protectors and by native code directly.
  [
    'android_dlopen_ext',
    'dlopen',
  ].forEach(hookNativeLoaderExport);
}

function stringifyJavaArg(a) {
  try {
    if (a === null || a === undefined) return String(a);
    return a.toString();
  } catch (e) {
    return `<toString failed: ${e}>`;
  }
}

function hookAllOverloads(className, methodName) {
  let C;
  try {
    C = Java.use(className);
  } catch (_) {
    return false;
  }

  const member = C[methodName];
  if (member === undefined || member.overloads === undefined) return false;

  member.overloads.forEach(ovl => {
    const sig = ovl.argumentTypes.map(t => t.className).join(', ');
    ovl.implementation = function () {
      const args = Array.prototype.slice.call(arguments);
      const argText = args.map(stringifyJavaArg).join(', ');
      const seq = ++callSeq;
      if (PRINT_JAVA_REQUESTS) {
        log(`[JAVA ${seq.toString().padStart(3, '0')}] ${className}.${methodName}(${sig}) args=[${argText}]`);
        printJavaBacktrace();
      }
      try {
        const ret = ovl.apply(this, args);
        if (PRINT_JAVA_REQUESTS) log(`[JRET ${seq.toString().padStart(3, '0')}] ${className}.${methodName} OK`);
        return ret;
      } catch (e) {
        warn(`[JEXC ${seq.toString().padStart(3, '0')}] ${className}.${methodName} threw ${e}`);
        throw e;
      }
    };
  });

  log(`[hook] ${className}.${methodName} (${member.overloads.length} overloads)`);
  return true;
}

function hookJavaLoaders() {
  if (!Java.available) {
    warn('Java runtime is not available in this process');
    return;
  }

  Java.perform(() => {
    try {
      const ActivityThread = Java.use('android.app.ActivityThread');
      const pkg = ActivityThread.currentPackageName();
      log(`[info] Android package seen by ActivityThread: ${pkg}`);
      if (pkg !== TARGET_PKG) warn(`[info] expected ${TARGET_PKG}; attached package is ${pkg}`);
    } catch (e) {
      warn(`[info] package lookup failed: ${e}`);
    }

    [
      ['java.lang.System', 'load'],
      ['java.lang.System', 'loadLibrary'],
      ['java.lang.Runtime', 'load'],
      ['java.lang.Runtime', 'loadLibrary'],
      ['java.lang.Runtime', 'load0'],
      ['java.lang.Runtime', 'loadLibrary0'],
      ['java.lang.Runtime', 'nativeLoad'],
      ['dalvik.system.BaseDexClassLoader', 'findLibrary'],
      ['dalvik.system.DexClassLoader', 'findLibrary'],
      ['dalvik.system.PathClassLoader', 'findLibrary'],
    ].forEach(([klass, method]) => hookAllOverloads(klass, method));
  });
}

rpc.exports = {
  // From frida REPL: await script.exports_sync.summary()
  summary() {
    return observedLoads;
  }
};

setImmediate(() => {
  rememberAllModules();
  printInitialSnapshot();
  hookNativeLoaders();
  hookJavaLoaders();
});
