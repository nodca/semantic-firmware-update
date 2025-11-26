import binascii
from typing import List, Dict, Tuple

def split_frames(patch_bytes: bytes, frame_payload_size: int = 502) -> Tuple[List[bytes], Dict]:
    total_crc = binascii.crc32(patch_bytes) & 0xFFFFFFFF
    frames: List[bytes] = []
    per_crc: List[int] = []
    n = len(patch_bytes)
    i = 0
    while i < n:
        chunk = patch_bytes[i:i+frame_payload_size]
        frames.append(chunk)
        per_crc.append(binascii.crc32(chunk) & 0xFFFFFFFF)
        i += frame_payload_size
    manifest = {
        'total_len': n,
        'total_crc32': total_crc,
        'frame_payload_size': frame_payload_size,
        'frames': len(frames),
        'frame_crc32': per_crc
    }
    return frames, manifest