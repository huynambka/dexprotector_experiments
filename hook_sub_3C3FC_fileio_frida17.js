'use strict';

/*
 * Frida 17.x: hook unpacked libdp sub_3C3FC and show readlink/open/lseek/read flow.
 *
 * Goal: answer what link/file it reads and what ELF/program-header data it extracts.
 *
 * Run:
 *   ./frida17/bin/frida -U -f com.dexprotector.detector.envchecks \
 *     -l hook_sub_3C3FC_fileio_frida17.js
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
const SUB_3C3FC_END   = ptr('0x3c640');
const SUB_3C218_START = ptr('0x3c218');
const QWORD_8CB10_RVA = ptr('0x8cb10');

// Instruction sites inside sub_3C3FC.
const SITES = {
  afterDecodePath: ptr('0x3c42c'),

  readlinkatSvc:   ptr('0x3c440'),
  readlinkatAfter: ptr('0x3c444'),

  openatSvc:       ptr('0x3c470'),
  openatAfter:     ptr('0x3c474'),

  readElfSvc:      ptr('0x3c49c'),
  readElfAfter:    ptr('0x3c4a0'),

  lseekSvc:        ptr('0x3c4f0'),
  lseekAfter:      ptr('0x3c4f4'),

  readPhdrSvc:     ptr('0x3c528'),
  readPhdrAfter:   ptr('0x3c52c'),

  beforeSub3C218:  ptr('0x3c5a8'),

  closeSuccessSvc: ptr('0x3c5c4'),
  closeFailSvc:    ptr('0x3c5dc'),

  storeDebugPtr:   ptr('0x3c624'),
};

const hooked = new Set();
const installedOuterBases = new Set();
const installedUnpackedBases = new Set();

let currentLoadBias = null;
const states = {}; // tid -> state while inside sub_3C3FC

function log(s) { console.log(s); }
function warn(s) { console.warn(s); }

function safeCString(p) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    return p.readCString();
  } catch (_) { return null; }
}

function safeUtf8(p, len) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    if (len !== undefined && len !== null) return p.readUtf8String(len);
    return p.readUtf8String();
  } catch (_) {
    return null;
  }
}

function readBytes(p, len) {
  try {
    if (p === null || p === undefined || p.isNull()) return null;
    const ab = p.readByteArray(len);
    if (ab === null) return null;
    return Array.from(new Uint8Array(ab));
  } catch (_) { return null; }
}

function bytesToHex(bytes, maxLen) {
  if (bytes === null) return '<read failed>';
  const a = maxLen ? bytes.slice(0, maxLen) : bytes;
  return a.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
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

function sret(p) {
  // Good enough for syscall returns used here: small positive or negative errno.
  try { return p.toInt32(); } catch (_) { return 0; }
}

function u64hex(p) {
  try { return '0x' + p.readU64().toString(16); } catch (_) { return '<bad64>'; }
}

function u32hex(p) {
  try { return '0x' + p.readU32().toString(16); } catch (_) { return '<bad32>'; }
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

function inSub3C3FC(ctx) {
  if (currentLoadBias === null) return false;
  const lr = ctx.lr;
  return ptrInRange(lr, currentLoadBias.add(SUB_3C3FC_START), currentLoadBias.add(SUB_3C3FC_END));
}

function st(tid) {
  return states[tid] || null;
}

function getTid(ctx) {
  // Frida supplies this.threadId in callbacks; this is just for places where we pass only context.
  return Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0;
}

function parseElfHeader(buf) {
  const magic = u32hex(buf);
  let e_phoff = '<bad>', e_phentsize = '<bad>', e_phnum = '<bad>';
  try {
    e_phoff = '0x' + buf.add(0x20).readU64().toString(16);
    e_phentsize = '0x' + buf.add(0x36).readU16().toString(16);
    e_phnum = '0x' + buf.add(0x38).readU16().toString(16);
  } catch (_) {}
  return { magic, e_phoff, e_phentsize, e_phnum };
}

function parsePhdr(buf) {
  try {
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
  } catch (_) { return null; }
}

function typeName(t) {
  if (t === 1) return 'PT_LOAD';
  if (t === 2) return 'PT_DYNAMIC';
  if (t === 3) return 'PT_INTERP';
  if (t === 4) return 'PT_NOTE';
  if (t === 6) return 'PT_PHDR';
  return 'PT_' + t;
}

function logPhdr(prefix, ph) {
  if (ph === null) { log(prefix + ' <parse failed>'); return; }
  log(`${prefix} type=${typeName(ph.p_type)}(${ph.p_type}) flags=0x${ph.p_flags.toString(16)} off=0x${ph.p_offset.toString(16)} vaddr=0x${ph.p_vaddr.toString(16)} filesz=0x${ph.p_filesz.toString(16)} memsz=0x${ph.p_memsz.toString(16)} align=0x${ph.p_align.toString(16)}`);
}

function installSub3C3FCHooks(loadBias) {
  const sub = loadBias.add(SUB_3C3FC_START);
  log(`[unpacked] load_bias=${loadBias} hook sub_3C3FC=${sub}`);

  attachOnce(sub, 'sub_3C3FC_entry_leave', {
    onEnter() {
      states[this.threadId] = {
        pathPtr: ptr(0),
        linkPath: null,
        linkBuf: ptr(0),
        linkTarget: null,
        fd: -1,
        elfBuf: ptr(0),
        phdrBuf: ptr(0),
        phdrIndex: 0,
        mapOut1: ptr(0),
        mapOut2: ptr(0),
      };
      log('\n[sub_3C3FC enter] reads /proc link, opens target ELF, scans phdr, extracts DT_DEBUG address');
    },
    onLeave(retval) {
      const ss = st(this.threadId);
      const q = loadBias.add(QWORD_8CB10_RVA);
      let qv = '<bad>';
      try { qv = q.readPointer().toString(); } catch (_) {}
      log(`[sub_3C3FC leave] ret=${retval} qword_8CB10=${qv}`);
      if (ss) {
        log(`[sub_3C3FC summary] readlink path="${ss.linkPath}" target="${ss.linkTarget}" fd=${ss.fd}`);
        delete states[this.threadId];
      }
      log('--- end sub_3C3FC ---\n');
    }
  });

  // After sub_401B0(dword_4143, buf, 15): X0 points decoded path.
  attachOnce(loadBias.add(SITES.afterDecodePath), 'sub_3C3FC_after_decode_path', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      ss.pathPtr = this.context.x0;
      ss.linkPath = safeCString(this.context.x0);
      log(`[decode] dword_4143 -> "${ss.linkPath}" @ ${this.context.x0}`);
    }
  });

  // readlinkat(AT_FDCWD, decoded_path, out_buf, 0xfff)
  attachOnce(loadBias.add(SITES.readlinkatSvc), 'sub_3C3FC_readlinkat_svc', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      ss.pathPtr = this.context.x1;
      ss.linkBuf = this.context.x2;
      ss.linkPath = safeCString(this.context.x1) || ss.linkPath;
      log(`[syscall readlinkat] no=78 dirfd=AT_FDCWD(-100) path="${ss.linkPath}" buf=${ss.linkBuf} size=${this.context.x3}`);
    }
  });

  attachOnce(loadBias.add(SITES.readlinkatAfter), 'sub_3C3FC_readlinkat_after', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      const n = sret(this.context.x0);
      let target = null;
      if (n >= 0 && n < 0x1000) {
        target = safeUtf8(ss.linkBuf, n);
        ss.linkTarget = target;
      }
      log(`[syscall readlinkat ret] x0=${this.context.x0} n=${n}` + (target !== null ? ` target="${target}"` : ''));
    }
  });

  // openat(AT_FDCWD, readlink_result, O_RDONLY=0)
  attachOnce(loadBias.add(SITES.openatSvc), 'sub_3C3FC_openat_svc', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      const path = safeCString(this.context.x1) || ss.linkTarget;
      log(`[syscall openat] no=56 dirfd=AT_FDCWD(-100) path="${path}" flags=${this.context.x2}`);
    }
  });

  attachOnce(loadBias.add(SITES.openatAfter), 'sub_3C3FC_openat_after', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      ss.fd = sret(this.context.x0);
      log(`[syscall openat ret] fd=${ss.fd} raw=${this.context.x0}`);
    }
  });

  // read(fd, elf_header_buf, 0x40)
  attachOnce(loadBias.add(SITES.readElfSvc), 'sub_3C3FC_read_elf_svc', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      ss.elfBuf = this.context.x1;
      log(`[syscall read ELF header] no=63 fd=${sret(this.context.x0)} buf=${this.context.x1} count=${this.context.x2}`);
    }
  });

  attachOnce(loadBias.add(SITES.readElfAfter), 'sub_3C3FC_read_elf_after', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      const n = sret(this.context.x0);
      const hdr = ss.elfBuf && !ss.elfBuf.isNull() ? parseElfHeader(ss.elfBuf) : null;
      const hex = ss.elfBuf && !ss.elfBuf.isNull() ? bytesToHex(readBytes(ss.elfBuf, Math.min(n > 0 ? n : 0x40, 0x40))) : '<no buf>';
      if (hdr) {
        log(`[syscall read ELF ret] n=${n} magic=${hdr.magic} e_phoff=${hdr.e_phoff} e_phentsize=${hdr.e_phentsize} e_phnum=${hdr.e_phnum}`);
      } else {
        log(`[syscall read ELF ret] n=${n}`);
      }
      log(`[ELF header hex] ${hex}`);
    }
  });

  // lseek(fd, e_phoff, SEEK_SET=0)
  attachOnce(loadBias.add(SITES.lseekSvc), 'sub_3C3FC_lseek_svc', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      log(`[syscall lseek] no=62 fd=${sret(this.context.x0)} offset=${this.context.x1} whence=${this.context.x2} // seek to ELF program header table`);
    }
  });

  attachOnce(loadBias.add(SITES.lseekAfter), 'sub_3C3FC_lseek_after', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      log(`[syscall lseek ret] x0=${this.context.x0} signed=${sret(this.context.x0)}`);
    }
  });

  // Loop: read(fd, phdr_buf, 0x38)
  attachOnce(loadBias.add(SITES.readPhdrSvc), 'sub_3C3FC_read_phdr_svc', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      ss.phdrBuf = this.context.x1;
      log(`[syscall read PHDR #${ss.phdrIndex}] no=63 fd=${sret(this.context.x0)} buf=${this.context.x1} count=${this.context.x2}`);
    }
  });

  attachOnce(loadBias.add(SITES.readPhdrAfter), 'sub_3C3FC_read_phdr_after', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      const n = sret(this.context.x0);
      const ph = ss.phdrBuf && !ss.phdrBuf.isNull() ? parsePhdr(ss.phdrBuf) : null;
      logPhdr(`[syscall read PHDR #${ss.phdrIndex} ret n=${n}]`, ph);
      ss.phdrIndex++;
    }
  });

  // sub_3C218(path, &mapBase, &outMaybe, 0): likely parse /proc/self/maps to map file path to runtime base.
  attachOnce(loadBias.add(SUB_3C218_START), 'sub_3C218_entry_leave_filtered', {
    onEnter(args) {
      this.active = inSub3C3FC(this.context);
      if (!this.active) return;
      this.path = args[0];
      this.out1 = args[1];
      this.out2 = args[2];
      const ss = st(this.threadId);
      if (ss) { ss.mapOut1 = this.out1; ss.mapOut2 = this.out2; }
      log(`[sub_3C218 enter] path="${safeCString(this.path)}" out1=${this.out1} out2=${this.out2} // map path to load address`);
    },
    onLeave(retval) {
      if (!this.active) return;
      const out1 = this.out1 && !this.out1.isNull() ? u64hex(this.out1) : '<null>';
      const out2 = this.out2 && !this.out2.isNull() ? u64hex(this.out2) : '<null>';
      log(`[sub_3C218 leave] ret=${retval} *out1=${out1} *out2=${out2}`);
    }
  });

  // Instruction right before BL sub_3C218, useful to show args too.
  attachOnce(loadBias.add(SITES.beforeSub3C218), 'sub_3C3FC_before_sub3C218', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      log(`[before sub_3C218] path="${safeCString(this.context.x0)}" x1(out1)=${this.context.x1} x2(out2)=${this.context.x2}`);
    }
  });

  attachOnce(loadBias.add(SITES.closeSuccessSvc), 'sub_3C3FC_close_success', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      log(`[syscall close success-path] no=57 fd=${sret(this.context.x0)}`);
    }
  });

  attachOnce(loadBias.add(SITES.closeFailSvc), 'sub_3C3FC_close_fail', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      log(`[syscall close fail-path] no=57 fd=${sret(this.context.x0)}`);
    }
  });

  attachOnce(loadBias.add(SITES.storeDebugPtr), 'sub_3C3FC_store_qword_8CB10', {
    onEnter() {
      const ss = st(this.threadId);
      if (!ss) return;
      log(`[store] qword_8CB10 <- ${this.context.x9} // value from DT_DEBUG entry (r_debug pointer)`);
    }
  });
}

function installUnpackedHooks(loadBias) {
  const key = loadBias.toString();
  if (installedUnpackedBases.has(key)) return;
  installedUnpackedBases.add(key);
  currentLoadBias = loadBias;
  installSub3C3FCHooks(loadBias);
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
      // Keep this short; useful to confirm unpack key spoof is active.
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

  // sub_167C(dynamic, load_bias, auxv, r_debug); install hooks early, before hidden init 0x4EB60 hashes code.
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
