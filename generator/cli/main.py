import argparse
import json
import os
import subprocess
import sys
from typing import Callable, Dict, Optional, Tuple

from generator.parsers.symbols import pair_symbols
from generator.tools import patch_stats
from generator.tools.framing import split_frames
from generator.utils.symbols import load_symbol_context

GenerateFn = Callable[..., Tuple[bytes, Dict[str, int]]]


def _verify_with_apply(old_path: str, new_path: str, patch_path: str, payload: int = 502) -> bool:
    cmd = [
        sys.executable, "-m", "generator.tools.apply_patch",
        "--old", old_path,
        "--patch", patch_path,
        "--expect", new_path,
        "--payload", str(payload),
    ]
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        print(f"[VERIFY] 运行失败: {e}")
        return False
    out = cp.stdout or ""
    print(out.strip())
    return cp.returncode == 0 and "[OK] 重建结果与期望固件一致" in out


def _print_patch_diagnostics(
    patch_bytes: bytes,
    stats: Dict[str, int],
    *,
    old_path: str,
    new_path: str,
    old_sym: Optional[str],
    new_sym: Optional[str],
    old_map: Optional[str],
    new_map: Optional[str],
    flash_base: int,
) -> None:
    total_ops = sum(stats.values())
    print(f"[STATS] 指令总数={total_ops} | COPY={stats.get('COPY',0)} "
          f"PATCH={stats.get('PATCH',0)} ADD={stats.get('ADD',0)} FILL={stats.get('FILL',0)} "
          f"PATCH_COMPACT={stats.get('PATCH_COMPACT',0)}")

    op_bytes = patch_stats.count_opcode_bytes(patch_bytes)
    total_bytes = sum(op_bytes.values()) or 1
    print("[COST] 指令类型字节开销:")
    for k, v in op_bytes.items():
        print(f"  {k}: bytes={v} pct={v/total_bytes*100:.2f}%")

    op_lens = patch_stats.collect_op_stats(patch_bytes)
    if op_lens["ADD"]:
        add_lens = op_lens["ADD"]
        avg_add = sum(add_lens) / len(add_lens)
        print(f"[DIAG] ADD 片段数={len(add_lens)} 总字节={sum(add_lens)} 平均长度={avg_add:.2f}")
        print(f"[DIAG] ADD Top10 长度={sorted(add_lens, reverse=True)[:10]}")
        if avg_add < 4:
            print("[DIAG] 注意: 平均 ADD 长度 <4, 分块过碎, 可尝试聚簇合并或提高 CDC 最小块大小.")
    if op_lens["COPY"]:
        copy_lens = op_lens["COPY"]
        print(f"[DIAG] COPY 片段数={len(copy_lens)} 总字节={sum(copy_lens)} 平均长度={sum(copy_lens)/len(copy_lens):.2f}")
        print(f"[DIAG] COPY Top10 长度={sorted(copy_lens, reverse=True)[:10]}")
    if op_lens["PATCH_COMPACT"]:
        pc_lens = op_lens["PATCH_COMPACT"]
        print(f"[DIAG] PATCH_COMPACT 区域数={len(pc_lens)} 平均长度={sum(pc_lens)/len(pc_lens):.2f}")
    if op_lens["PATCH"]:
        p_lens = op_lens["PATCH"]
        print(f"[DIAG] PATCH 区域数={len(p_lens)} 平均长度={sum(p_lens)/len(p_lens):.2f}")

    meta_bytes, data_bytes = patch_stats.count_meta_data_bytes(patch_bytes)
    total_meta = sum(meta_bytes.values())
    total_data = sum(data_bytes.values())
    denom = total_meta + total_data or 1
    print("[META] 指令元数据字节开销:")
    try:
        with open(old_path, 'rb') as f:
            old_bin = f.read()
        with open(new_path, 'rb') as f:
            new_bin = f.read()
        old_len = len(old_bin)
        new_len = len(new_bin)
        old_syms_raw, _ = load_symbol_context(old_sym, old_map, flash_base, old_len)
        new_syms_raw, _ = load_symbol_context(new_sym, new_map, flash_base, new_len)
        semantic_bytes = 0
        if old_syms_raw and new_syms_raw:
            pairs = pair_symbols(old_syms_raw, new_syms_raw, old_len, new_len)
            for n_off, _, size in pairs:
                size = min(size, new_len - n_off)
                if size > 0:
                    semantic_bytes += size
        hole_bytes = new_len - semantic_bytes
        print(f"[COVERAGE] 语义区覆盖={semantic_bytes} bytes ({semantic_bytes/new_len*100:.2f}%) | "
              f"空洞区={hole_bytes} bytes ({hole_bytes/new_len*100:.2f}%)")
    except Exception as e:
        print(f"[COVERAGE] 语义区覆盖统计失败: {e}")
    for k in meta_bytes:
        data = data_bytes.get(k, 0)
        print(f"  {k}: meta_bytes={meta_bytes[k]} data_bytes={data} "
              f"meta_pct={meta_bytes[k]/denom*100:.2f}% data_pct={data/denom*100:.2f}%")
    print(f"  总元数据: {total_meta} bytes, 总数据: {total_data} bytes, 总补丁: {total_meta+total_data} bytes")


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="语义感知固件差分补丁生成器（含 502B 分片）")
    sub = ap.add_subparsers(dest='cmd', required=True)

    g = sub.add_parser('gen', help='生成补丁')
    g.add_argument('--old', required=True, help='旧固件 bin')
    g.add_argument('--new', required=True, help='新固件 bin')
    g.add_argument('--old-sym', default=None, help='旧符号 JSON')
    g.add_argument('--new-sym', default=None, help='新符号 JSON')
    g.add_argument('--old-map', default=None, help='旧固件 map')
    g.add_argument('--new-map', default=None, help='新固件 map')
    g.add_argument('--flash-base', default='0x08000000', help='FLASH 基地址')
    g.add_argument('--out', required=True, help='输出补丁文件')
    g.add_argument('--frames', default=None, help='分片输出目录')
    g.add_argument('--frame-size', type=int, default=502, help='每片有效载荷字节数')
    g.add_argument('--cdc', action='store_true', help='启用 CDC 匹配策略（仅高级模式）')
    g.add_argument('--arch-mode', default='auto', choices=['auto','thumb','arm','raw'], help='ARM 架构模式')
    g.add_argument('--endian', default='le', choices=['le','be'], help='端序')
    g.add_argument('--mode', default='global', choices=['global', 'advanced'],
                   help='选择补丁生成模式')
    g.add_argument('--reloc-aware', action='store_true', help='启用重定位/指令模式相似性判断')
    g.add_argument('--reloc-th', type=float, default=0.6, help='语义区进入阈值（0-1）')
    g.add_argument('--reloc-filter', action='store_true', help='当相似度低于阈值时丢弃语义区')
    g.add_argument('--reloc-debug', action='store_true', help='打印相似度分项以便诊断')
    g.add_argument("--verify", action="store_true", help="生成后用设备端应用器校验（apply_patch.py）")
    g.add_argument("--payload", type=int, default=502, help="校验时模拟设备端每片有效载荷字节数，默认 502")
    g.add_argument('--speed-profile', default='balanced', choices=['balanced', 'fast'],
                   help='速度/体积权衡：balanced（默认）或 fast（更快生成，可能轻微增大补丁）')
    return ap


def run_cli(
    generate_patch_global_fn: GenerateFn,
    generate_patch_fn: GenerateFn,
) -> None:
    ap = _build_arg_parser()
    args = ap.parse_args()
    try:
        flash_base = int(args.flash_base, 0)
    except Exception:
        print("[ERROR] --flash-base 格式错误", file=sys.stderr)
        sys.exit(2)

    if args.mode == 'global':
        print("[MODE] 使用 global 语义匹配路径（首选）")
        patch_bytes, stats = generate_patch_global_fn(
            args.old,
            args.new,
            old_sym_json=args.old_sym,
            new_sym_json=args.new_sym,
            flash_base=flash_base,
            arch_mode=args.arch_mode,
            endian=args.endian,
            speed_profile=args.speed_profile,
        )
    else:
        print("[MODE] 使用 advanced 语义差分路径")
        patch_bytes, stats = generate_patch_fn(
            args.old, args.new,
            old_sym_json=args.old_sym, new_sym_json=args.new_sym,
            old_map=args.old_map, new_map=args.new_map,
            flash_base=flash_base,
            use_cdc=args.cdc,
            arch_mode=args.arch_mode,
            reloc_aware=args.reloc_aware,
            reloc_th=args.reloc_th,
            reloc_filter=args.reloc_filter,
            reloc_debug=args.reloc_debug,
            endian=args.endian,
        )

    with open(args.out, 'wb') as f:
        f.write(patch_bytes)
    print(f"[OK] 补丁已生成: {args.out}, 长度 {len(patch_bytes)} bytes")
    _print_patch_diagnostics(
        patch_bytes,
        stats,
        old_path=args.old,
        new_path=args.new,
        old_sym=args.old_sym,
        new_sym=args.new_sym,
        old_map=args.old_map,
        new_map=args.new_map,
        flash_base=flash_base,
    )

    if args.frames:
        os.makedirs(args.frames, exist_ok=True)
        frames, manifest = split_frames(patch_bytes, frame_payload_size=args.frame_size)
        for i, ch in enumerate(frames):
            with open(os.path.join(args.frames, f'frame_{i:05d}.bin'), 'wb') as f:
                f.write(ch)
        with open(os.path.join(args.frames, 'manifest.json'), 'w', encoding='utf-8') as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        print(f"[OK] 已输出分片到 {args.frames}, 共 {len(frames)} 片 每片有效载荷 {args.frame_size}B")
        print(f"[OK] manifest.json: total_len={manifest['total_len']} total_crc32=0x{manifest['total_crc32']:08X}")

    if args.verify:
        ok = _verify_with_apply(args.old, args.new, args.out, payload=args.payload)
        if ok:
            print("[VERIFY] OK: apply_patch 重建与新固件一致")
        else:
            print("[VERIFY] FAIL: apply_patch 重建与新固件不一致")
            if args.mode == 'global':
                print("[VERIFY] 已在 global 模式下，无法继续回退")
                sys.exit(2)
            print("[VERIFY] fallback: 尝试使用全局匹配生成的简单补丁 (global-only)")
            patch_bytes2, stats2 = generate_patch_global_fn(
                args.old,
                args.new,
                min_match_len=16,
                old_sym_json=args.old_sym,
                new_sym_json=args.new_sym,
                flash_base=flash_base,
                arch_mode=args.arch_mode,
                endian=args.endian,
            )
            with open(args.out, 'wb') as f:
                f.write(patch_bytes2)
            print(f"[FALLBACK] 已生成 global-only 补丁到 {args.out}, size={len(patch_bytes2)}")
            ok2 = _verify_with_apply(args.old, args.new, args.out, payload=args.payload)
            if ok2:
                print("[VERIFY] OK: fallback global-only 补丁重建与新固件一致")
            else:
                print("[VERIFY] FAIL: fallback global-only 补丁仍然不一致")
                sys.exit(2)
