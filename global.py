#!/usr/bin/env python3
from generator.generate import generate_patch_global_only

def main():
    old = "QLS01CDHS224.bin"
    new = "QLS01CDHS225.bin"
    out = "QLS01CDHSpatch_global.bin"

    old_sym = "QLS01CDHS224.json"
    new_sym = "QLS01CDHS225.json"

    patch_bytes, stats = generate_patch_global_only(
        old, new,
        min_match_len=16,
        old_sym_json=old_sym,
        new_sym_json=new_sym,
        flash_base=0x00000000,   # QLS 情况
        arch_mode="arm",
        endian="be",             # QLS 是大端 ELF
    )
    with open(out, "wb") as f:
        f.write(patch_bytes)

    total_ops = sum(stats.values())
    print(f"[GLOBAL] patch written to {out}, size={len(patch_bytes)} bytes")
    print(f"[GLOBAL] ops={total_ops} | "
          f"COPY={stats.get('COPY',0)} PATCH={stats.get('PATCH',0)} "
          f"ADD={stats.get('ADD',0)} FILL={stats.get('FILL',0)} "
          f"PATCH_COMPACT={stats.get('PATCH_COMPACT',0)}")

if __name__ == "__main__":
    main()
