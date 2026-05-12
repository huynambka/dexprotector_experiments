'use strict';

/*
 * Safer Frida 17.x hook for sub_3C3FC.
 *
 * It does NOT hook raw SVC/lseek/read instruction sites. Those inline hooks can disturb
 * this protected function. Instead, when sub_3C3FC is entered, this script reproduces
 * the same harmless /proc/self/exe -> ELF-header -> PHDR read in JS using libc calls,
 * then onLeave prints qword_8CB10 (the r_debug pointer sub_3C3FC extracted).
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l hook_sub_3C3FC_fileio_safe_frida17.js
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
const SUB_3C3FC_START = ptr('0x3c3fc');
const QWORD_8CB10_RVA = ptr('0x8cb10');

const AT_FDCWD = -100;
const O_RDONLY = 0;
const SEEK_SET = 0;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;

const hooked = new Set();
const installedOuterBases = new Set();
const installedUnpackedBases = new Set();
let currentLoadBias = null;

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

function findExport(name) {
  let p = null;

  // Frida <=16 style
  if (typeof Module.findExportByName === 'function') {
    try { p = Module.findExportByName('libc.so', name); } catch (_) {}
    if (p === null) { try { p = Module.findExportByName(null, name); } catch (_) {} }
  }

  // Frida 17 style: global export helpers
  if (p === null && typeof Module.findGlobalExportByName === 'function') {
    try { p = Module.findGlobalExportByName(name); } catch (_) {}
  }
  if (p === null && typeof Module.getGlobalExportByName === 'function') {
    try { p = Module.getGlobalExportByName(name); } catch (_) {}
  }

  // Frida 17 style: Module object methods
  if (p === null && typeof Process.findModuleByName === 'function') {
    const libc = Process.findModuleByName('libc.so');
    if (libc !== null) {
      if (typeof libc.findExportByName === 'function') {
        try { p = libc.findExportByName(name); } catch (_) {}
      }
      if (p === null && typeof libc.getExportByName === 'function') {
        try { p = libc.getExportByName(name); } catch (_) {}
      }
    }
  }
  if (p === null && typeof Process.getModuleByName === 'function') {
    try {
      const libc = Process.getModuleByName('libc.so');
      if (typeof libc.getExportByName === 'function') p = libc.getExportByName(name);
    } catch (_) {}
  }

  if (p === null) throw new Error(`cannot find libc export ${name}`);
  return p;
}

const c_readlinkat = new NativeFunction(findExport('readlinkat'), 'long', ['int', 'pointer', 'pointer', 'ulong']);
const c_openat     = new NativeFunction(findExport('openat'),     'int',  ['int', 'pointer', 'int', 'int']);
const c_read       = new NativeFunction(findExport('read'),       'long', ['int', 'pointer', 'ulong']);
const c_lseek      = new NativeFunction(findExport('lseek'),      'long', ['int', 'long', 'int']);
const c_close      = new NativeFunction(findExport('close'),      'int',  ['int']);

function hex64(v) {
  try { return '0x' + v.toString(16); } catch (_) { return String(v); }
}

function typeName(t) {
  if (t === 1) return 'PT_LOAD';
  if (t === 2) return 'PT_DYNAMIC';
  if (t === 3) return 'PT_INTERP';
  if (t === 4) return 'PT_NOTE';
  if (t === 6) return 'PT_PHDR';
  if (t === 7) return 'PT_TLS';
  if (t === 0x6474e550) return 'PT_GNU_EH_FRAME';
  if (t === 0x6474e551) return 'PT_GNU_STACK';
  if (t === 0x6474e552) return 'PT_GNU_RELRO';
  return 'PT_' + t;
}

function parseElf64Header(buf) {
  return {
    magic: '0x' + buf.readU32().toString(16),
    e_type: buf.add(0x10).readU16(),
    e_machine: buf.add(0x12).readU16(),
    e_entry: buf.add(0x18).readU64(),
    e_phoff: buf.add(0x20).readU64(),
    e_shoff: buf.add(0x28).readU64(),
    e_ehsize: buf.add(0x34).readU16(),
    e_phentsize: buf.add(0x36).readU16(),
    e_phnum: buf.add(0x38).readU16(),
  };
}

function parsePhdr(buf) {
  return {
    p_type: buf.add(0x00).readU32(),
    p_flags: buf.add(0x04).readU32(),
    p_offset: buf.add(0x08).readU64(),
    p_vaddr: buf.add(0x10).readU64(),
    p_paddr: buf.add(0x18).readU64(),
    p_filesz: buf.add(0x20).readU64(),
    p_memsz: buf.add(0x28).readU64(),
    p_align: buf.add(0x30).readU64(),
  };
}

function logPhdr(i, ph) {
  log(`[probe PHDR #${i}] type=${typeName(ph.p_type)}(${ph.p_type}) flags=0x${ph.p_flags.toString(16)} off=${hex64(ph.p_offset)} vaddr=${hex64(ph.p_vaddr)} filesz=${hex64(ph.p_filesz)} memsz=${hex64(ph.p_memsz)} align=${hex64(ph.p_align)}`);
}

function probeProcSelfExeLikeSub3C3FC() {
  const linkPath = '/proc/self/exe'; // first run proved dword_4143 decodes to this
  const linkPathPtr = Memory.allocUtf8String(linkPath);
  const linkBuf = Memory.alloc(0x1000);

  log(`[probe] readlinkat(AT_FDCWD, "${linkPath}", buf, 0xfff)`);
  const n = Number(c_readlinkat(AT_FDCWD, linkPathPtr, linkBuf, 0xfff));
  if (n < 0) {
    log(`[probe] readlinkat failed ret=${n}`);
    return;
  }

  linkBuf.add(n).writeU8(0);
  const target = linkBuf.readUtf8String(n);
  log(`[probe] ${linkPath} -> "${target}" len=${n}`);

  const targetPtr = Memory.allocUtf8String(target);
  const fd = c_openat(AT_FDCWD, targetPtr, O_RDONLY, 0);
  log(`[probe] openat(AT_FDCWD, "${target}", O_RDONLY) -> fd=${fd}`);
  if (fd < 0) return;

  try {
    const eh = Memory.alloc(0x40);
    const rn = Number(c_read(fd, eh, 0x40));
    if (rn !== 0x40) {
      log(`[probe] read ELF header failed/short n=${rn}`);
      return;
    }

    const hdr = parseElf64Header(eh);
    log(`[probe ELF] magic=${hdr.magic} e_type=${hdr.e_type} e_machine=${hdr.e_machine} e_phoff=${hex64(hdr.e_phoff)} e_phentsize=0x${hdr.e_phentsize.toString(16)} e_phnum=${hdr.e_phnum}`);
    log(`[probe ELF hex] ${bytesToHex(readBytes(eh, 0x40))}`);

    const seekRet = Number(c_lseek(fd, Number(hdr.e_phoff), SEEK_SET));
    log(`[probe] lseek(fd, ${hex64(hdr.e_phoff)}, SEEK_SET) -> ${seekRet}`);
    if (seekRet < 0) return;

    const phbuf = Memory.alloc(0x38);
    let firstLoadVaddr = null;
    let firstDynamicVaddr = null;
    for (let i = 0; i < hdr.e_phnum; i++) {
      const pn = Number(c_read(fd, phbuf, 0x38));
      if (pn !== 0x38) {
        log(`[probe] read PHDR #${i} short n=${pn}`);
        return;
      }
      const ph = parsePhdr(phbuf);
      logPhdr(i, ph);
      if (ph.p_type === PT_LOAD && firstLoadVaddr === null) firstLoadVaddr = ph.p_vaddr;
      if (ph.p_type === PT_DYNAMIC && firstDynamicVaddr === null) firstDynamicVaddr = ph.p_vaddr;
    }
    log(`[probe summary] first PT_LOAD vaddr=${firstLoadVaddr === null ? '<none>' : hex64(firstLoadVaddr)} first PT_DYNAMIC vaddr=${firstDynamicVaddr === null ? '<none>' : hex64(firstDynamicVaddr)}`);
  } finally {
    c_close(fd);
  }
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

  const sub = loadBias.add(SUB_3C3FC_START);
  log(`[unpacked] load_bias=${loadBias} hook sub_3C3FC=${sub}`);

  attachOnce(sub, 'sub_3C3FC_safe_entry_leave', {
    onEnter() {
      log('\n[sub_3C3FC enter] safe probe, no inline SVC hooks');
      try { probeProcSelfExeLikeSub3C3FC(); }
      catch (e) { warn(`[probe error] ${e.stack || e}`); }
    },
    onLeave(retval) {
      let qv = '<bad>';
      try { qv = currentLoadBias.add(QWORD_8CB10_RVA).readPointer().toString(); } catch (_) {}
      log(`[sub_3C3FC leave] ret=${retval} qword_8CB10=${qv}`);
      log('--- end sub_3C3FC ---\n');
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
