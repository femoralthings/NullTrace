"""
core/alpha_lsb.py — Alpha channel LSB steganography

PNG and other lossless formats support RGBA — a 4th channel controlling
pixel transparency (0=fully transparent, 255=fully opaque).

Changing the LSB of the alpha channel alters opacity by 1/255 (~0.4%).
This is imperceptible to the human eye and to most image analysis tools
which focus exclusively on the RGB channels.

Key properties:
  - Completely independent of RGB data — no colour changes at all
  - Statistical analysis of RGB channels finds nothing
  - Only affects images that actually USE the alpha channel (RGBA)
  - Images with uniform alpha (e.g., all 255) will have uniform LSBs
    after embedding — this is detectable. Best used on images with
    natural alpha variation (transparent PNGs, layered graphics).

Same PRNG spread as lsb.py — password-derived Fisher-Yates shuffle.
"""

import os
import struct
import hashlib
import random
from pathlib import Path
from PIL import Image

SUPPORTED    = {'.png', '.tiff', '.tif'}   # formats that natively support alpha
LENGTH_BYTES = 4


def _spread_seed(password: str) -> int:
    h = hashlib.sha256(b"nulltrace-alpha-spread:" + password.encode()).digest()
    return int.from_bytes(h, 'big')


def _get_pixel_order(password: str, n_pixels: int) -> list:
    rng     = random.Random(_spread_seed(password))
    indices = list(range(n_pixels))
    rng.shuffle(indices)
    return indices


def _bytes_to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
    result = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            chunk += [0] * (8 - len(chunk))
        result.append(int(''.join(str(b) for b in chunk), 2))
    return bytes(result)


def capacity(image_path: str) -> int:
    """Return payload capacity in bytes (1 bit per pixel via alpha channel)."""
    img = Image.open(image_path).convert('RGBA')
    w, h = img.size
    return (w * h) // 8 - LENGTH_BYTES


def hide(image_path: str, payload: bytes, password: str,
         output_path: str) -> None:
    """
    Embed payload into the LSB of the alpha channel.
    The image MUST be saved as PNG or TIFF to preserve alpha.
    RGB channels are untouched — only transparency values change.
    """
    path = Path(image_path)
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError(
            f"Alpha LSB requires PNG or TIFF (supports alpha channel). "
            f"Got: '{path.suffix}'"
        )

    stat = os.stat(image_path)
    original_times = (stat.st_atime, stat.st_mtime)

    original = Image.open(image_path)
    original_info = original.info.copy()
    img      = original.convert('RGBA')
    pixels   = list(img.getdata())
    n_pixels = len(pixels)

    framed = struct.pack('<I', len(payload)) + payload
    bits   = _bytes_to_bits(framed)

    if len(bits) > n_pixels:
        cap = n_pixels // 8 - LENGTH_BYTES
        raise ValueError(
            f"Payload too large ({len(payload)} bytes). "
            f"Alpha channel capacity: {cap} bytes."
        )

    pixel_order = _get_pixel_order(password, n_pixels)
    pixels_mut  = [list(p) for p in pixels]

    # Embed one bit per pixel into alpha channel (index 3)
    for bit_pos, bit in enumerate(bits):
        pix_idx = pixel_order[bit_pos]
        pixels_mut[pix_idx][3] = (pixels_mut[pix_idx][3] & 0xFE) | bit

    out_img = Image.new('RGBA', img.size)
    out_img.putdata([tuple(p) for p in pixels_mut])

    save_kwargs = {}
    if 'icc_profile' in original_info:
        save_kwargs['icc_profile'] = original_info['icc_profile']

    # Always save as PNG to preserve alpha
    out_path = Path(output_path)
    if out_path.suffix.lower() not in ('.png', '.tiff', '.tif'):
        output_path = str(out_path.with_suffix('.png'))

    out_img.save(output_path, **save_kwargs)
    os.utime(output_path, original_times)


def extract(image_path: str, password: str) -> bytes:
    """
    Extract payload from alpha channel LSBs.
    Returns raw (still-encrypted) bytes.
    """
    img      = Image.open(image_path).convert('RGBA')
    pixels   = list(img.getdata())
    n_pixels = len(pixels)

    pixel_order = _get_pixel_order(password, n_pixels)

    def read_bits(n_bits: int, start: int) -> list:
        return [pixels[pixel_order[start + i]][3] & 1 for i in range(n_bits)]

    length_bits = read_bits(32, 0)
    length      = struct.unpack('<I', _bits_to_bytes(length_bits))[0]

    if length == 0 or length > n_pixels // 8:
        raise ValueError(
            "No valid alpha channel payload found "
            "(wrong password or image contains no hidden data)."
        )

    payload_bits = read_bits(length * 8, 32)
    return _bits_to_bytes(payload_bits)


def scan(image_path: str) -> dict:
    """
    Blind scan: analyze alpha channel LSB distribution.
    Uniform alpha (all 255 or all 0) is normal.
    Near-50/50 LSB ratio on a normally-opaque image is suspicious.
    """
    result = {'detected': False, 'findings': []}

    try:
        img = Image.open(image_path)
        if img.mode != 'RGBA':
            result['findings'].append("Image has no alpha channel (not RGBA)")
            return result

        pixels      = list(img.getdata())
        alpha_vals  = [p[3] for p in pixels]
        unique_alpha = len(set(alpha_vals))

        if unique_alpha == 1:
            result['findings'].append(
                f"Uniform alpha ({alpha_vals[0]}) — no information in alpha channel"
            )
            return result

        lsbs  = [a & 1 for a in alpha_vals]
        ratio = sum(lsbs) / len(lsbs)

        if 0.47 <= ratio <= 0.53:
            result['detected'] = True
            result['findings'].append(
                f"Alpha channel LSB ratio {ratio:.4f} — "
                f"near 50/50, consistent with embedded encrypted data"
            )
        else:
            result['findings'].append(
                f"Alpha channel LSB ratio {ratio:.4f} (normal)"
            )

    except Exception as e:
        result['findings'].append(f"Error scanning alpha channel: {e}")

    return result
