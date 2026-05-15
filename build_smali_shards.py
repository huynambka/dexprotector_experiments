#!/usr/bin/env python3
"""Build a large patched smali tree into multiple dex shards to avoid 64K method_id limits."""
import argparse, os, shutil, subprocess, sys
from pathlib import Path

CP = 'tools/tools/m2deps/*'

def copy_files(files, src_root, dst_root):
    if dst_root.exists(): shutil.rmtree(dst_root)
    for f in files:
        rel = f.relative_to(src_root)
        out = dst_root / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, out)

def assemble(smali_dir, out_dex, log_file):
    out_dex.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['java','-cp',CP,'org.jf.smali.Main','assemble','-o',str(out_dex),str(smali_dir)]
    with open(log_file, 'w') as lf:
        p = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, text=True)
    return p.returncode

def build_group(files, src_root, work_root, out_root, prefix, depth=0, min_split=1):
    idx = prefix
    smali_dir = work_root / f'smali_{idx}'
    out_dex = out_root / f'classes0_fullpatched_part{idx}.dex'
    log_file = out_root / f'classes0_fullpatched_part{idx}.log'
    copy_files(files, src_root, smali_dir)
    rc = assemble(smali_dir, out_dex, log_file)
    if rc == 0 and out_dex.exists():
        print(f'OK {idx}: files={len(files)} dex={out_dex} size={out_dex.stat().st_size}')
        return [(idx, len(files), out_dex)]
    log = log_file.read_text(errors='replace') if log_file.exists() else ''
    if len(files) <= min_split:
        print(f'FAIL {idx}: files={len(files)} log={log_file}')
        print(log[:2000])
        return []
    # Split on method_id/dex index pressure; also helpful for most writer range errors.
    mid = len(files)//2
    print(f'SPLIT {idx}: files={len(files)} rc={rc} -> {len(files[:mid])}+{len(files[mid:])} log={log_file}')
    return (build_group(files[:mid], src_root, work_root, out_root, idx+'a', depth+1, min_split) +
            build_group(files[mid:], src_root, work_root, out_root, idx+'b', depth+1, min_split))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', default='build/classes0_smali_patched')
    ap.add_argument('--work', default='build/classes0_fullpatched_shards')
    ap.add_argument('--out', default='build/out/classes0_fullpatched_shards')
    ap.add_argument('--chunk', type=int, default=500)
    args=ap.parse_args()
    src=Path(args.inp)
    work=Path(args.work); out=Path(args.out)
    if work.exists(): shutil.rmtree(work)
    if out.exists(): shutil.rmtree(out)
    work.mkdir(parents=True); out.mkdir(parents=True)
    files=sorted(src.rglob('*.smali'))
    groups=[files[i:i+args.chunk] for i in range(0,len(files),args.chunk)]
    results=[]
    for n,g in enumerate(groups):
        results += build_group(g, src, work, out, f'{n:02d}')
    manifest=out/'manifest.txt'
    manifest.write_text('\n'.join(f'{idx}\t{count}\t{dex}' for idx,count,dex in results)+'\n')
    print(f'DONE shards={len(results)} manifest={manifest}')

if __name__=='__main__':
    main()
