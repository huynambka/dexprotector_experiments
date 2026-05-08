'use strict';

/*
 * Frida 17.x: dump the unpacked libdp.so memory image AFTER libdexprotector's
 * custom linker applies relocations.
 *
 * Run early:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l hook_dump_after_reloc_frida17.js
 *
 * Dumps on device:
 *   /data/data/com.dexprotector.detector.envchecks/files/dp_reloc_dumps/
 *
 * Pull:
 *   adb shell 'su -c "ls -l /data/data/com.dexprotector.detector.envchecks/files/dp_reloc_dumps"'
 *   adb shell 'su -c "cat /data/data/com.dexprotector.detector.envchecks/files/dp_reloc_dumps/after_sub167c_full_reloc_image_0x90000.bin"' \
 *     > dumps/after_sub167c_full_reloc_image_0x90000.bin
 */

const TARGET_LIB = 'libdexprotector.so';
const TARGET_INIT_RVA = ptr('0x378');

const DP_SUB_167C_RVA = ptr('0x167c');
// In sub_167C: after both sub_1820() calls succeeded, right before memset(symtab..strtab) at 0x17e0.
// RELA/JMPREL are already applied, but their entries are already zeroed by sub_1820().
// RELR is NOT applied yet here, and symtab/strtab are still present.
const DP_SUB_167C_AFTER_RELA_BEFORE_WIPE_RVA = ptr('0x17d0');

const DUMP_DIR = '/data/data/com.dexprotector.detector.envchecks/files/dp_reloc_dumps';
const IMAGE_SIZE = 0x90000;
const CHUNKS = [
  { name: 'chunk_00', off: 0x00000, size: 0x7caa0 },
  { name: 'chunk_01', off: 0x80aa0, size: 0x4208  },
  { name: 'chunk_02', off: 0x88cb0, size: 0x1a5c  },
];

const hooked = new Set();
const installedBases = new Set();
const activeSub167cByTid = {};
let depth = 0;

function log(s) { console.log(s); }
function warn(s) { console.warn(s); }

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

function mkdirOne(path) {
  try {
    const p = findExport('mkdir');
    if (p === null) return false;
    const mkdir = new NativeFunction(p, 'int', ['pointer', 'int']);
    mkdir(Memory.allocUtf8String(path), 0x1c0); // 0700
    return true;
  } catch (_) { return false; }
}

function describeAddress(p) {
  try {
    if (!p || p.isNull()) return String(p);
    const m = Process.findModuleByAddress(p);
    if (m === null) return p.toString();
    return `${p} ${m.name}+0x${p.sub(m.base).toString(16)} ${m.path}`;
  } catch (_) { return String(p); }
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

function findTargetModule(path) {
  let m = Process.findModuleByName(TARGET_LIB);
  if (m !== null) return m;
  return Process.enumerateModules().find(x => x.path === path || x.path.indexOf(TARGET_LIB) !== -1 || x.name === TARGET_LIB) || null;
}

function isTargetPath(s) { return s !== null && s.indexOf(TARGET_LIB) !== -1; }
function sanitize(s) { return String(s).replace(/[^a-zA-Z0-9_.-]/g, '_'); }

function dumpMemoryToFile(filePath, addr, len) {
  const data = addr.readByteArray(len);
  if (data === null) throw new Error('readByteArray returned null');
  const f = new File(filePath, 'wb');
  try { f.write(data); f.flush(); } finally { f.close(); }
}

function writeZeros(f, len) {
  if (len <= 0) return;
  const block = new Uint8Array(Math.min(len, 0x4000));
  let left = len;
  while (left > 0) {
    const n = Math.min(left, block.length);
    f.write(block.buffer.slice(0, n));
    left -= n;
  }
}

function dumpCombinedImage(tag, loadBias) {
  mkdirOne(DUMP_DIR);
  const safeTag = sanitize(tag);

  // Dump individual real chunks. Do not read gaps: they may still be PROT_NONE.
  for (const c of CHUNKS) {
    const p = loadBias.add(c.off);
    const out = `${DUMP_DIR}/${safeTag}_${c.name}_off_${c.off.toString(16)}_size_${c.size.toString(16)}.bin`;
    try {
      dumpMemoryToFile(out, p, c.size);
      log(`[dump ${tag}] ${c.name} ${p} off=0x${c.off.toString(16)} size=0x${c.size.toString(16)} -> ${out}`);
    } catch (e) {
      warn(`[dump ${tag}] failed ${c.name} @ ${p}: ${e}`);
    }
  }

  // Also create one 0x90000 image with zero-filled gaps.
  const imgPath = `${DUMP_DIR}/${safeTag}_image_0x90000.bin`;
  const f = new File(imgPath, 'wb');
  try {
    let cur = 0;
    for (const c of CHUNKS) {
      if (c.off > cur) writeZeros(f, c.off - cur);
      const data = loadBias.add(c.off).readByteArray(c.size);
      if (data === null) throw new Error(`readByteArray returned null for ${c.name}`);
      f.write(data);
      cur = c.off + c.size;
    }
    if (cur < IMAGE_SIZE) writeZeros(f, IMAGE_SIZE - cur);
    f.flush();
    log(`[dump ${tag}] combined image -> ${imgPath}`);
  } catch (e) {
    warn(`[dump ${tag}] combined image failed: ${e}`);
  } finally {
    try { f.close(); } catch (_) {}
  }
}

function attachOnce(addr, label, handlers) {
  const k = `${label}@${addr}`;
  if (hooked.has(k)) return;
  hooked.add(k);
  Interceptor.attach(addr, handlers);
  log(`[hooked ${label}] ${describeAddress(addr)}`);
}

function installDexprotectorHooks(path) {
  const m = findTargetModule(path);
  if (m === null) {
    warn(`[${TARGET_LIB}] not visible yet for path=${path}`);
    return;
  }

  const baseKey = m.base.toString();
  if (installedBases.has(baseKey)) return;
  installedBases.add(baseKey);

  log(`[${TARGET_LIB}] base=${m.base} path=${m.path}`);
  mkdirOne(DUMP_DIR);

  attachOnce(m.base.add(DP_SUB_167C_RVA), 'sub_167C entry/leave', {
    onEnter(args) {
      this.dynamic = args[0];
      this.loadBias = args[1];
      this.auxv = args[2];
      this.rdebug = args[3];
      activeSub167cByTid[this.threadId] = {
        dynamic: this.dynamic,
        loadBias: this.loadBias,
        auxv: this.auxv,
        rdebug: this.rdebug,
      };
      log(`[sub_167C enter] dynamic=${this.dynamic} load_bias=${this.loadBias} auxv=${this.auxv} r_debug=${this.rdebug}`);
    },
    onLeave(retval) {
      log(`[sub_167C leave] retval=${retval} dynamic=${this.dynamic} load_bias=${this.loadBias}`);
      try {
        if ((retval.toInt32() & 1) !== 0) {
          dumpCombinedImage('after_sub167c_full_reloc', this.loadBias);
        }
      } catch (e) {
        warn(`[sub_167C leave] dump failed: ${e}`);
      }
      delete activeSub167cByTid[this.threadId];
    }
  });

  attachOnce(m.base.add(DP_SUB_167C_AFTER_RELA_BEFORE_WIPE_RVA), 'sub_167C after RELA before wipe', {
    onEnter() {
      const st = activeSub167cByTid[this.threadId];
      if (st === undefined) {
        warn('[sub_167C mid] no active state for thread');
        return;
      }
      // At this PC: both sub_1820 calls succeeded. Symtab/strtab not wiped yet. RELR not applied yet.
      log(`[sub_167C mid] after RELA/JMPREL, before symtab/strtab wipe; load_bias=${st.loadBias} dynamic=${st.dynamic}`);
      dumpCombinedImage('after_rela_jmprel_before_symwipe_no_relr', st.loadBias);
    }
  });
}

function main() {
  const linker = findLinkerModule();
  if (!linker) { warn('linker/linker64 not found'); return; }
  log(`[linker] ${linker.name} base=${linker.base} path=${linker.path}`);

  let syms;
  try { syms = enumSymbols(linker); } catch (e) { warn('enumerate linker symbols failed: ' + e); return; }

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

  ctorSyms.forEach(s => {
    log(`[hook] call_constructors ${s.name} @ ${s.address}`);
    Interceptor.attach(s.address, {
      onEnter(args) {
        this.si = args[0];
        this.path = soinfoPath(this.si);
        this.d = depth++;
        if (isTargetPath(this.path)) {
          log(`${'  '.repeat(this.d)}[call_constructors ENTER] ${this.path}`);
          installDexprotectorHooks(this.path);
        }
      },
      onLeave() {
        depth--;
        if (isTargetPath(this.path)) log(`${'  '.repeat(this.d)}[call_constructors LEAVE] ${this.path}`);
      }
    });
  });

  if (ctorSyms.length === 0) warn('No call_constructors symbols found in linker');
}

setImmediate(main);
