import os
import re
import json
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

class Symbol:
    def __init__(self, name: str, off: int, size: int):
        self.name = name
        self.off = off
        self.size = size

def load_symbols_from_json(sym_json_path: Optional[str]) -> Dict[str, List[Symbol]]:
    # 同时支持两种结构：
    # A) 结构形式：{"symbols": {"foo": {"file_offset":..., "size":...}, ...}}
    # B) 结构形式：{"flash_base": 0x..., "symbols": [{"name":"foo","addr":...,"size":...}, ...]}
    if not sym_json_path or not os.path.isfile(sym_json_path):
        return {}
    with open(sym_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    grouped: Dict[str, List[Symbol]] = defaultdict(list)
    syms = data.get('symbols', data)  # 兼容根即为 symbols 的情况
    flash_base_in_json = int(data.get('flash_base', 0)) if isinstance(data, dict) else 0

    # 结构 B：list
    if isinstance(syms, list):
        for ent in syms:
            if not isinstance(ent, dict):
                continue
            name = ent.get('name') or ent.get('symbol') or ent.get('func') or ""
            if not name or not _good_sym_name(name):
                continue
            size = int(ent.get('size', 0) or 0)
            if size <= 0:
                continue
            # ===== 修改此处：优先使用 addr =====
            off = None
            if 'addr' in ent and flash_base_in_json > 0:  # 有效 flash_base 时优先用 addr
                off = int(ent['addr']) - flash_base_in_json
            elif 'file_offset' in ent:
                off = int(ent['file_offset'])
            elif 'off' in ent:
                off = int(ent['off'])
            
            if off is None or off < 0:
                continue
            
            grouped[name].append(Symbol(name, off, size))
        for lst in grouped.values():
            lst.sort(key=lambda s: s.off)
        return grouped

    # 结构 A：dict
    if isinstance(syms, dict):
        for name, meta in syms.items():
            if not _good_sym_name(name):
                continue
            if isinstance(meta, dict):
                # 支持 file_offset/size 或 addr/size
                size = int(meta.get('size', 0) or 0)
                if size <= 0:
                    continue
                # ===== 修改此处：优先使用 addr =====
                off = None
                if 'addr' in meta and flash_base_in_json > 0:
                    off = int(meta['addr']) - flash_base_in_json
                elif 'file_offset' in meta:
                    off = int(meta['file_offset'])
                elif 'off' in meta:
                    off = int(meta['off'])
                
                if off is None or off < 0:
                    continue
                
                grouped[name].append(Symbol(name, off, size))
            elif isinstance(meta, list):
                # 支持同名多段的列表
                for seg in meta:
                    try:
                        size = int(seg.get('size', 0) or 0)
                        if size <= 0:
                            continue
                        # ===== 关键修复：使用 seg 而不是 meta =====
                        off = None
                        if 'addr' in seg and flash_base_in_json > 0:
                            off = int(seg['addr']) - flash_base_in_json
                        elif 'file_offset' in seg:
                            off = int(seg['file_offset'])
                        elif 'off' in seg:
                            off = int(seg['off'])
                        
                        if off is None or off < 0:
                            continue
                        
                        grouped[name].append(Symbol(name, off, size))
                    except Exception:
                        continue
        for lst in grouped.values():
            lst.sort(key=lambda s: s.off)
        return grouped

    # 其他未知结构
    return {}
FLASH_MIN = 0x08000000
FLASH_MAX = 0x08FFFFFF
_ADDR = re.compile(r'\b0x([0-9a-fA-F]+)\b')

def _good_sym_name(name: str) -> bool:
    # 原有的过滤条件
    bad_prefix = ('$', '.L', '.__', '@', '__thumb$')
    
    if not name:
        return False
        
    # IAR C++符号通常以"??"开头，这些应该保留
    if name.startswith('??'):
        return True
        
    # 过滤其他不良前缀
    if name.startswith(bad_prefix):
        return False
        
    # 允许常见的有效符号模式
    good_patterns = ('main', 'init', 'handler', 'isr', 'task', 'function', 'interrupt')
    if any(pattern in name.lower() for pattern in good_patterns):
        return True
        
    # 允许较短的符号名（之前是>2，现在放宽到>=2）
    return len(name) >= 2

def load_symbols_from_map(map_path: Optional[str], flash_base: int, img_len: int) -> Dict[str, List[Symbol]]:
    if not map_path or not os.path.isfile(map_path):
        return {}
    with open(map_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    entries: List[Tuple[int, str]] = []
    addr_lo = flash_base
    addr_hi = flash_base + max(0, img_len)
    for ln in lines:
        addrs = [int(m.group(1), 16) for m in _ADDR.finditer(ln)]
        addr = None
        for a in addrs:
            if addr_lo <= a <= addr_hi:
                addr = a
                break
        if addr is None:
            continue
        tokens = [t for t in re.split(r'\s+', ln.strip()) if t]
        if not tokens:
            continue
        name = None
        for tk in reversed(tokens):
            if _ADDR.fullmatch(tk) or tk.isdigit() or '\\' in tk or '/' in tk:
                continue
            tk = tk.rstrip(',:')
            if _good_sym_name(tk):
                name = tk
                break
        if not name:
            continue
        entries.append((addr, name))
    if not entries:
        return {}
    entries.sort(key=lambda x: (x[0], x[1]))
    dedup: List[Tuple[int, str]] = []
    last_addr = None
    last_name = None
    for addr, name in entries:
        if last_addr == addr:
            if _good_sym_name(name) and (not last_name or not _good_sym_name(last_name)):
                dedup[-1] = (addr, name)
                last_name = name
            continue
        dedup.append((addr, name))
        last_addr, last_name = addr, name
    grouped: Dict[str, List[Symbol]] = defaultdict(list)
    for i, (addr, name) in enumerate(dedup):
        next_addr = dedup[i + 1][0] if i + 1 < len(dedup) else addr
        size = max(0, next_addr - addr)
        off = addr - flash_base
        if off < 0:
            continue
        if size <= 0:
            continue
        grouped[name].append(Symbol(name, off, size))
    for lst in grouped.values():
        lst.sort(key=lambda s: s.off)
    return grouped

def _score_syms(syms: Dict[str, List[Symbol]], img_len: int) -> int:
    total = 0
    for lst in syms.values():
        for s in lst:
            if s.off < 0 or s.off >= img_len or s.size <= 0:
                continue
            total += max(0, min(s.size, img_len - s.off))
    return total

def _merge_syms(primary: Dict[str, List[Symbol]], secondary: Dict[str, List[Symbol]]) -> Dict[str, List[Symbol]]:
    out: Dict[str, List[Symbol]] = {}
    for k, v in primary.items():
        out[k] = list(v)
    for k, v in secondary.items():
        if k not in out or not out[k]:
            out[k] = list(v)
    return out

def load_symbols_any(sym_json: Optional[str], map_path: Optional[str], flash_base: int, img_len: int) -> Tuple[Optional[dict], Dict[str, List[Symbol]]]:
    """
    加载符号，同时返回原始 JSON 数据（如果存在）和解析后的符号字典。
    返回 (raw_json_dict, parsed_symbols_dict)
    """
    raw_data = None
    parsed_syms = {}

    # 优先使用 JSON
    if sym_json and os.path.isfile(sym_json):
        with open(sym_json, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
        # 从原始数据中解析
        js = _parse_json_data(raw_data)
        mp = load_symbols_from_map(map_path, flash_base=flash_base, img_len=img_len) if map_path else {}
        s_js = _score_syms(js, img_len)
        s_mp = _score_syms(mp, img_len)
        parsed_syms = _merge_syms(js, mp) if s_js >= s_mp else _merge_syms(mp, js)
    
    # 如果没有 JSON，则只用 MAP
    elif map_path and os.path.isfile(map_path):
        parsed_syms = load_symbols_from_map(map_path, flash_base=flash_base, img_len=img_len)
        # 为 MAP 文件伪造一个 raw_data 结构
        raw_data = {
            "flash_base": flash_base,
            "symbols": [{"name": s.name, "addr": s.off + flash_base, "size": s.size} for lst in parsed_syms.values() for s in lst]
        }
    
    return raw_data, parsed_syms

def _parse_json_data(data: dict) -> Dict[str, List[Symbol]]:
    """Parse symbols from the JSON dump, tolerating different layouts."""
    grouped: Dict[str, List[Symbol]] = defaultdict(list)
    flash_base = int(data.get('flash_base', 0x08000000))

    def _append_symbol(name: str, off: Optional[int], size: int) -> None:
        if off is None or off < 0 or size <= 0:
            return
        if not _good_sym_name(name):
            return
        grouped[name].append(Symbol(name, off, size))

    sections = data.get('sections')
    if isinstance(sections, dict):
        print(f"  [解析] 检测到 sections 结构，共 {len(sections)} 个段")
        for sec_idx, sec_info in sections.items():
            if not isinstance(sec_info, dict):
                continue
            symbols = sec_info.get('symbols')
            if not isinstance(symbols, dict):
                continue
            print(f"  [解析] 段 {sec_idx} 包含 {len(symbols)} 个符号")
            for sym_name, sym_info in symbols.items():
                if not isinstance(sym_info, dict):
                    continue
                size = int(sym_info.get('size', 0) or 0)
                if size <= 0:
                    continue
                off = None
                if 'addr' in sym_info and flash_base > 0:
                    off = int(sym_info['addr']) - flash_base
                elif 'file_offset' in sym_info:
                    off = int(sym_info['file_offset'])
                elif 'off' in sym_info:
                    off = int(sym_info['off'])
                _append_symbol(sym_name, off, size)

    syms = data.get('symbols', data)
    if isinstance(syms, list):
        print(f"  [解析] 检测到列表格式符号表，共 {len(syms)} 个条目")
        for ent in syms:
            if not isinstance(ent, dict):
                continue
            size = int(ent.get('size', 0) or 0)
            if size <= 0:
                continue
            off = None
            if 'addr' in ent and flash_base > 0:
                off = int(ent['addr']) - flash_base
            elif 'file_offset' in ent:
                off = int(ent['file_offset'])
            elif 'off' in ent:
                off = int(ent['off'])
            name = ent.get('name') or ent.get('symbol') or ent.get('func') or ''
            _append_symbol(name, off, size)
        for lst in grouped.values():
            lst.sort(key=lambda s: s.off)
        return grouped

    if isinstance(syms, dict):
        print(f"  [解析] 检测到字典格式符号表，共 {len(syms)} 个条目")
        for name, meta in syms.items():
            if isinstance(meta, dict):
                size = int(meta.get('size', 0) or 0)
                off = None
                if 'addr' in meta and flash_base > 0:
                    off = int(meta['addr']) - flash_base
                elif 'file_offset' in meta:
                    off = int(meta['file_offset'])
                elif 'off' in meta:
                    off = int(meta['off'])
                _append_symbol(name, off, size)
            elif isinstance(meta, list):
                for seg in meta:
                    if not isinstance(seg, dict):
                        continue
                    size = int(seg.get('size', 0) or 0)
                    off = None
                    if 'addr' in seg and flash_base > 0:
                        off = int(seg['addr']) - flash_base
                    elif 'file_offset' in seg:
                        off = int(seg['file_offset'])
                    elif 'off' in seg:
                        off = int(seg['off'])
                    _append_symbol(name, off, size)
        for lst in grouped.values():
            lst.sort(key=lambda s: s.off)
        return grouped

    print("  [解析] 尝试直接在顶级查找符号字典")
    for name, value in data.items():
        if not isinstance(value, dict):
            continue
        size = int(value.get('size', 0) or 0)
        if size <= 0:
            continue
        off = None
        if 'addr' in value and flash_base > 0:
            off = int(value['addr']) - flash_base
        elif 'file_offset' in value:
            off = int(value['file_offset'])
        elif 'off' in value:
            off = int(value['off'])
        _append_symbol(name, off, size)

    for lst in grouped.values():
        lst.sort(key=lambda s: s.off)
    print(f"  [解析] 最终提取到 {len(grouped)} 个符号")
    return grouped

def _flatten_raw_symbols(raw: Optional[dict]) -> List[dict]:
    """
    将原始 JSON 或 map 派生的数据统一扁平化为:
    [{'name': str, 'addr': int, 'size': int}, ...]
    兼容以下情况：
    - {'flash_base': ..., 'symbols': [ {name, addr|off, size}, ... ] }
    - {'flash_base': ..., 'symbols': { name: {addr|off|file_offset,size} | [segments...] } }
    - 直接是 { name: {...} } 这样的字典
    """
    if not isinstance(raw, dict):
        return []
    base = int(raw.get('flash_base', 0))
    syms = raw.get('symbols', raw)

    flat: List[dict] = []
    # 情况1：已是列表
    if isinstance(syms, list):
        for ent in syms:
            if not isinstance(ent, dict):
                continue
            name = ent.get('name') or ent.get('symbol') or ent.get('func')
            size = ent.get('size')
            if not name or not size:
                continue
            if 'addr' in ent:
                addr = int(ent['addr'])
            elif 'off' in ent:
                addr = int(ent['off']) + base
            elif 'file_offset' in ent:
                addr = int(ent['file_offset']) + base
            else:
                continue
            flat.append({'name': name, 'addr': addr, 'size': int(size)})
        return flat

    # 情况2：是字典（name -> meta 或 segments）
    if isinstance(syms, dict):
        # 借助已有解析逻辑，得到分组的 Symbol 列表（off 为文件内偏移）
        grouped = _parse_json_data({'flash_base': base, 'symbols': syms})
        for name, lst in grouped.items():
            for s in lst:
                flat.append({'name': name, 'addr': int(s.off) + base, 'size': int(s.size)})
        return flat

    return flat

def pair_symbols(old_syms_raw: dict, new_syms_raw: dict, old_len: int, new_len: int) -> List[Tuple[int, int, int]]:
    """
    根据原始符号表（兼容多种 JSON 结构）配对，返回 (n_off, o_off, size)。
    """
    old_base = int(old_syms_raw.get('flash_base', 0)) if isinstance(old_syms_raw, dict) else 0
    new_base = int(new_syms_raw.get('flash_base', 0)) if isinstance(new_syms_raw, dict) else 0

    old_list = _flatten_raw_symbols(old_syms_raw)
    new_list = _flatten_raw_symbols(new_syms_raw)

    old_map = {}
    for ent in old_list:
        try:
            old_map[ent['name']] = {'addr': int(ent['addr']), 'size': int(ent['size'])}
        except Exception:
            continue

    pairs: List[Tuple[int, int, int]] = []
    for ent in new_list:
        try:
            name = ent['name']
            n_addr = int(ent['addr'])
            n_size = int(ent['size'])
        except Exception:
            continue
        o_ent = old_map.get(name)
        if not o_ent:
            continue
        o_addr = o_ent['addr']
        o_size = o_ent['size']

        n_off = n_addr - new_base
        o_off = o_addr - old_base
        if n_off < 0 or o_off < 0 or n_off >= new_len or o_off >= old_len:
            continue

        size = max(0, min(o_size, n_size))
        if size <= 0:
            continue
        pairs.append((n_off, o_off, size))

    # 可按新文件偏移排序，便于后续处理
    pairs.sort(key=lambda t: t[0])
    return pairs
def merge_adjacent_symbol_regions(pairs: List[Tuple[int, int, int]], 
                                 old_bin: bytes, new_bin: bytes, 
                                 merge_threshold: int = 64,
                                 debug: bool = False) -> List[Tuple[int, int, int]]:
    """
    合并相邻的符号区域，如果它们形成连续匹配
    
    Args:
        pairs: 符号配对列表 [(n_off, o_off, size), ...]
        old_bin: 旧固件二进制数据
        new_bin: 新固件二进制数据  
        merge_threshold: 合并阈值，小于此值的间隙允许合并
        debug: 是否输出调试信息
    
    Returns:
        合并后的符号区域列表
    """
    if not pairs or len(pairs) <= 1:
        return pairs
    
    # 按新固件偏移排序
    sorted_pairs = sorted(pairs, key=lambda x: x[0])
    
    merged = []
    current_n, current_o, current_size = sorted_pairs[0]
    
    if debug:
        print(f"[MERGE] 开始合并 {len(pairs)} 个符号区域")
        print(f"[MERGE] 初始区域: n_off=0x{current_n:08X}, o_off=0x{current_o:08X}, size={current_size}")
    
    for i in range(1, len(sorted_pairs)):
        n_off, o_off, size = sorted_pairs[i]
        
        # 检查是否连续
        gap_n = n_off - (current_n + current_size)
        gap_o = o_off - (current_o + current_size)
        
        is_continuous = (gap_n == 0 and gap_o == 0)
        is_small_gap = (0 < gap_n <= merge_threshold and gap_n == gap_o)
        
        if is_continuous or is_small_gap:
            # 验证间隙区域是否匹配（对于有小间隙的情况）
            if is_small_gap:
                old_gap = old_bin[current_o + current_size:current_o + current_size + gap_n]
                new_gap = new_bin[current_n + current_size:current_n + current_size + gap_n]
                if old_gap != new_gap:
                    # 间隙不匹配，不能合并
                    if debug:
                        print(f"[MERGE] 间隙不匹配，不能合并区域 {i}")
                    merged.append((current_n, current_o, current_size))
                    current_n, current_o, current_size = n_off, o_off, size
                    continue
            
            # 可以合并，扩展当前区域
            old_end = current_o + current_size
            new_end = current_n + current_size
            extended_size = (n_off + size) - current_n
            
            if debug:
                print(f"[MERGE] 合并区域 {i}: n_off=0x{n_off:08X}, o_off=0x{o_off:08X}, size={size}")
                if is_small_gap:
                    print(f"[MERGE] 包含间隙: {gap_n} 字节")
            
            current_size = extended_size
            
        else:
            # 不连续，保存当前区域
            if debug:
                print(f"[MERGE] 区域不连续: gap_n={gap_n}, gap_o={gap_o}, 保存当前区域")
            merged.append((current_n, current_o, current_size))
            current_n, current_o, current_size = n_off, o_off, size
    
    # 添加最后一个区域
    merged.append((current_n, current_o, current_size))
    
    if debug:
        print(f"[MERGE] 合并完成: {len(pairs)} -> {len(merged)} 个区域")
        total_original = sum(size for _, _, size in pairs)
        total_merged = sum(size for _, _, size in merged)
        print(f"[MERGE] 总字节数: {total_original} -> {total_merged} 字节")
        
        # 显示最大的几个区域
        large_regions = sorted(merged, key=lambda x: x[2], reverse=True)[:5]
        print(f"[MERGE] 最大区域: {[(f'0x{n:08X}', size) for n, o, size in large_regions]}")
    
    return merged

def safe_merge_symbol_regions(pairs: List[Tuple[int, int, int]], 
                             old_bin: bytes, new_bin: bytes,
                             debug: bool = False) -> List[Tuple[int, int, int]]:
    """
    安全的符号区域合并，包含错误处理和回退机制
    """
    try:
        if not pairs:
            return pairs
            
        merged = merge_adjacent_symbol_regions(
            pairs, old_bin, new_bin, 
            merge_threshold=64,  # 允许最多64字节的间隙
            debug=debug
        )
        
        # 验证合并结果的有效性
        if len(merged) > len(pairs):
            raise ValueError("合并后区域数量异常增加")
            
        # 验证偏移和大小有效性
        for n_off, o_off, size in merged:
            if n_off < 0 or o_off < 0 or size <= 0:
                raise ValueError(f"无效的区域参数: n_off=0x{n_off:08X}, o_off=0x{o_off:08X}, size={size}")
                
        return merged
        
    except Exception as e:
        print(f"[MERGE-WARNING] 符号区域合并失败: {e}")
        print(f"[MERGE-WARNING] 使用原始符号区域: {len(pairs)} 个区域")
        return pairs  # 失败时回退到原始区域
#