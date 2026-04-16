"""
core/lsb.py — LSB steganography for lossless images (PNG, BMP, TIFF)

LSB = Least Significant Bit. Every pixel has R, G, B values (0-255).
Flipping the last bit changes a color value by 1 — completely invisible.
That gives us 3 bits of storage per pixel. A 1920x1080 image = ~787KB capacity.

Anti-detection: bits are spread across pixels in a password-derived PRNG order
instead of sequentially. Sequential embedding is detectable by chi-square and RS
statistical analysis. PRNG spread makes the LSB plane look like natural image noise.

File timestamps are preserved to avoid modification date fingerprinting.
EXIF and ICC profiles are preserved from the original.
"""

import os
import struct
import hashlib
import random
from pathlib import Path
from PIL import Image

SUPPORTED = {'.png', '.bmp', '.tiff', '.tif'}
LENGTH_BYTES = 4  # 4-byte little-endian payload length header


def _spread_seed(password: str) -> int:
    """
    Derive a deterministic integer seed from the password.
    Uses a domain-separation prefix so this seed is independent from
    the encryption key derived in crypto.py.
    """
    h = hashlib.sha256(b"nulltrace-lsb-spread:" + password.encode('utf-8')).digest()
    return int.from_bytes(h, 'big')


def _get_pixel_order(password: str, n_pixels: int) -> list:
    """
    Shuffle pixel indices using a password-seeded PRNG (Fisher-Yates).
    Same password + same image size = identical pixel order every time.
    This is how extraction reconstructs the same sequence without any stored state.
    """
    rng = random.Random(_spread_seed(password))
    indices = list(range(n_pixels))
    rng.shuffle(indices)
    return indices


def _bytes_to_bits(data: bytes) -> list:
    """Convert bytes to a flat list of bits, MSB first."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
    """Pack a flat list of bits (MSB first) back into bytes."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            chunk += [0] * (8 - len(chunk))
        result.append(int(''.join(str(b) for b in chunk), 2))
    return bytes(result)


def capacity(image_path: str) -> int:
    """Return maximum payload size in bytes for this image."""
    img = Image.open(image_path)
    w, h = img.size
    # 3 channels × 1 bit per channel = 3 bits per pixel → bytes = pixels×3÷8
    # Subtract 4-byte length header
    return (w * h * 3) // 8 - LENGTH_BYTES


def hide(image_path: str, payload: bytes, password: str, output_path: str) -> None:
    """
    Embed payload into image LSBs using PRNG-ordered pixel selection.

    Embedding layout (bit positions map to pixel_order[pos//3], channel pos%3):
        bits 0-31     → 4-byte little-endian payload length
        bits 32+      → encrypted payload bytes

    Metadata (EXIF, ICC profile) and original timestamps are preserved.
    """
    path = Path(image_path)
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError(f"Unsupported format '{path.suffix}'. Use PNG, BMP, or TIFF.")

    # Snapshot original timestamps before touching the file
    stat = os.stat(image_path)
    original_times = (stat.st_atime, stat.st_mtime)

    original = Image.open(image_path)
    original_info = original.info.copy()
    img = original.convert('RGB')

    pixels = list(img.getdata())
    n_pixels = len(pixels)

    framed_payload = struct.pack('<I', len(payload)) + payload
    required_bits  = len(framed_payload) * 8

    if required_bits > n_pixels * 3:
        cap = (n_pixels * 3) // 8 - LENGTH_BYTES
        raise ValueError(
            f"Payload too large ({len(payload)} bytes). "
            f"This image holds max {cap} bytes."
        )

    bits         = _bytes_to_bits(framed_payload)
    pixel_order  = _get_pixel_order(password, n_pixels)
    pixels_mut   = [list(p) for p in pixels]

    for bit_pos, bit in enumerate(bits):
        pix_idx = pixel_order[bit_pos // 3]
        channel = bit_pos % 3               # 0=R, 1=G, 2=B
        pixels_mut[pix_idx][channel] = (pixels_mut[pix_idx][channel] & 0xFE) | bit

    out_img = Image.new('RGB', img.size)
    out_img.putdata([tuple(p) for p in pixels_mut])

    # Re-attach original metadata
    save_kwargs = {}
    if 'exif' in original_info:
        save_kwargs['exif'] = original_info['exif']
    if 'icc_profile' in original_info:
        save_kwargs['icc_profile'] = original_info['icc_profile']
    if 'dpi' in original_info:
        save_kwargs['dpi'] = original_info['dpi']

    out_img.save(output_path, **save_kwargs)

    # Restore timestamps on the output to match the source file
    os.utime(output_path, original_times)


def extract(image_path: str, password: str) -> bytes:
    """
    Reconstruct payload from image LSBs using the same PRNG pixel order.
    Returns raw (still-encrypted) bytes — caller passes through crypto.decrypt().
    """
    img = Image.open(image_path).convert('RGB')
    pixels     = list(img.getdata())
    n_pixels   = len(pixels)
    pixel_order = _get_pixel_order(password, n_pixels)

    def read_n_bits(n_bits: int, start_bit: int) -> list:
        bits = []
        for i in range(n_bits):
            pos     = start_bit + i
            pix_idx = pixel_order[pos // 3]
            channel = pos % 3
            bits.append(pixels[pix_idx][channel] & 1)
        return bits

    # Read 32-bit length header
    length_bits  = read_n_bits(32, 0)
    length_bytes = _bits_to_bytes(length_bits)
    length       = struct.unpack('<I', length_bytes)[0]

    if length == 0 or length > (n_pixels * 3) // 8:
        raise ValueError(
            "No valid payload found (wrong password, or image contains no hidden data)."
        )

    # Read payload
    payload_bits = read_n_bits(length * 8, 32)
    return _bits_to_bytes(payload_bits)
