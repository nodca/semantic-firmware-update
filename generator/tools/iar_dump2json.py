#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, argparse, subprocess, glob, shutil
from typing import Optional

def find_ielfdumparm(user_path: Optional[str]) -> str:
    if user_path:
        return user_path
    # 环境变量优先
    envp = os.environ.get("IAR_IELFDUMPARM")
    if envp and os.path.isfile(envp):
        return envp
    # 同目录优先
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ielfdumparm.exe")
    if os.path.isfile(local):
        return local
    # 查找 PATH
    which = shutil.which("ielfdumparm.exe")
    if which and os.path.isfile(which):
        return which
    candidates = []
    for base in [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")]:
        if not base: continue
        pattern = os.path.join(base, "IAR Systems", "Embedded Workbench*", "arm", "bin", "ielfdumparm.exe")
        candidates.extend(glob.glob(pattern))
    for p in candidates:
        if os.path.isfile(p):
            return p
    raise SystemExit("未找到 ielfdumparm.exe，请用 --ielfdumparm 指定完整路径，或设置环境变量 IAR_IELFDUMPARM。")

def run_ielfdumparm(ielfdumparm: str, elf_path: str) -> str:
    # 捕获 stdout 文本
    try:
        cp = subprocess.run([ielfdumparm, "--all", elf_path],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.stderr.decode(errors="ignore"))
        raise SystemExit(f"ielfdumparm 运行失败，exit={e.returncode}")
    return cp.stdout.decode("utf-8", errors="ignore")

def main():
    ap = argparse.ArgumentParser(description="一键：ielfdumparm .out -> dump.txt -> JSON")
    ap.add_argument("elf", help="IAR 链接输出 .out/.elf 路径")
    ap.add_argument("--out", required=True, help="输出 JSON 路径")
    ap.add_argument("--dump-txt", help="可选：保存的 dump 文本路径（默认与 JSON 同名 .txt）")
    ap.add_argument("--ielfdumparm", help="ielfdumparm.exe 路径（未指定则自动探测）")
    ap.add_argument("--addr-min", type=lambda x:int(x,0), help="符号地址最小值（支持 0x 前缀）")
    ap.add_argument("--addr-max", type=lambda x:int(x,0), help="符号地址最大值")
    args = ap.parse_args()

    elf_path = os.path.abspath(args.elf)
    if not os.path.isfile(elf_path):
        raise SystemExit(f"找不到 ELF/OUT 文件: {elf_path}")
    out_json = os.path.abspath(args.out)
    dump_txt = os.path.abspath(args.dump_txt) if args.dump_txt else os.path.splitext(out_json)[0] + ".txt"

    tool = find_ielfdumparm(args.ielfdumparm)
    print(f"[1/2] 运行 ielfdumparm：{tool}")
    txt = run_ielfdumparm(tool, elf_path)
    os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
    with open(dump_txt, "w", encoding="utf-8") as f:
        f.write(txt)
    print(f"[OK] dump 写入：{dump_txt} 大小={len(txt):,} 字节")

    # 复用现有 dump.py 解析
    try:
        import generator.tools.dump as dump_mod  # 对应的 dump.py 模块路径（例如 c:\Users\...\my_chafen\dump.py）
    except Exception as e:
        raise SystemExit(f"无法导入 dump.py：{e}")
    dump_mod.ADDR_MIN = args.addr_min
    dump_mod.ADDR_MAX = args.addr_max

    print("[2/2] 解析 dump 为 JSON...")
    data = dump_mod.parse_iar_dump(dump_txt)
    import json
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    seg = data.get("segment", {})
    print(f"[OK] JSON 写入：{out_json}")
    if seg:
        print(f"  LOAD 段: VAddr=0x{seg.get('vaddr',0):08X}, FileOff=0x{seg.get('file_offset',0):X}")
    print(f"  节区: {len(data.get('sections', {}))} | 符号: {len(data.get('symbols', {}))}")

if __name__ == "__main__":
    main()
