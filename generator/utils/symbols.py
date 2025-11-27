import os
from typing import Dict, Optional, Tuple

from generator.parsers.symbols import load_symbols_any


def load_symbol_context(
    sym_path: Optional[str],
    map_path: Optional[str],
    flash_base: int,
    bin_len: int,
) -> Tuple[Optional[dict], Dict]:
    """
    Load raw/parsed symbols if the given path exists; otherwise return empty defaults.
    """
    if sym_path and os.path.isfile(sym_path):
        try:
            return load_symbols_any(sym_path, map_path, flash_base, bin_len)
        except Exception:
            pass
    return None, {}

