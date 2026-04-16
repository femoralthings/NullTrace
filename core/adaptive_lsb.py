"""
core/adaptive_lsb.py — Adaptive LSB steganography

Standard LSB embeds uniformly across all pixels. This is detectable because
smooth image regions (sky, skin, solid backgrounds) should have correlated
LSBs — but after embedding, those LSBs become random, which RS analysis catches.

Adaptive LSB only embeds in HIGH-COMPLEXITY pixels: edges, textures, noise.
In these areas, 1-bit changes are statistically indistinguishable from natural
image variation. The result is undetectable even under RS and WS analysis.

How complexity is measured:
  Local variance in a 3x3 neighbourhood around each pixel.
  Variance > threshold → pixel qualifies for embedding.

Capacity varies by image content:
  - Smooth gradients / solid colour: low capacity (few complex pixels)
  - Natural photos / textures: high capacity (~60-80% of standard LSB)
  - Noise-heavy images: near full capacity

Same PRNG spread as lsb.py — password-derived Fisher-Yates over the
qualifying pixel pool for additional statistical immunity.
"""

import os
import struct
import hashlib
import random
from pathlib import Path
from PIL import Image

SUPPORTED      = {'.png', '.bmp', '.tiff', '.tif'}
LENGTH_BYTES   = 4
VARIANCE_THRESHOLD = 8   # pixels with local variance > this qualify


def _spread_seed(password: str) -> int:
    h = hashlib.sha256(b"nulltrace-adaptive-spread:" + password.encode()).digest()
    return int.from_bytes(h, 'big')


def _local_variance(pixels, idx: int, width: int, height: int) -> float:
    """Compute luminance variance of the 3x3 neighbourhood around pixel idx."""
    x = idx % width
    y = idx // width

    vals = []
    for dy in range(-1, 2):
        for dx in range(-1, 2):
            nx, ny = x + dx, y + dy
            if 0 <= nx < width and 0 <= ny < height:
                p = pixels[ny * width + nx]
                # Perceived luminance
                vals.append(0.299 * p[0] + 0.587 * p[1] + 0.114 * p[2])

    if not vals:
        return 0.0
    mean = sum(vals) / len(vals)
    return sum((v - mean) ** 2 for v in vals) / len(vals)


def _qualifying_pixels(pixels, width: int, height: int,
                       password: str) -> list:
    """
    Return PRNG-shuffled list of pixel indices whose local variance
    exceeds VARIANCE_THRESHOLD. Same password + same image = same list.
    """
    n = width * height
    candidates = [
        i for i in range(n)
        if _local_variance(pixels, i, width, height) > VARIANCE_THRESHOLD
    ]
    rng = random.Random(_spread_seed(password))
    rng.shuffle(candidates)
    return candidates


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


def capacity(image_path: str, password: str) -> int:
    """
    Return payload capacity in bytes for this image + password combination.
    Depends on image content — textured images have more qualifying pixels.
    """
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    w, h = img.size
    qualifying = _qualifying_pixels(pixels, w, h, password)
    return (len(qualifying) * 3) // 8 - LENGTH_BYTES


def hide(image_path: str, payload: bytes, password: str,
         output_path: str) -> int:
    """
    Embed payload into high-complexity pixels only.
    Returns number of qualifying pixels used.
    Preserves metadata and timestamps.
    """
    path = Path(image_path)
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError(f"Unsupported format '{path.suffix}'. Use PNG, BMP, or TIFF.")

    stat = os.stat(image_path)
    original_times = (stat.st_atime, stat.st_mtime)

    original = Image.open(image_path)
    original_info = original.info.copy()
    img = original.convert('RGB')
    w, h = img.size
    pixels = list(img.getdata())

    qualifying = _qualifying_pixels(pixels, w, h, password)
    framed     = struct.pack('<I', len(payload)) + payload
    bits       = _bytes_to_bits(framed)

    max_bits = len(qualifying) * 3
    if len(bits) > max_bits:
        cap = max_bits // 8 - LENGTH_BYTES
        raise ValueError(
            f"Payload too large ({len(payload)} bytes). "
            f"Adaptive capacity for this image: {cap} bytes. "
            f"Use a more textured image or standard LSB."
        )

    pixels_mut = [list(p) for p in pixels]

    for bit_pos, bit in enumerate(bits):
        pix_idx = qualifying[bit_pos // 3]
        channel = bit_pos % 3
        pixels_mut[pix_idx][channel] = (pixels_mut[pix_idx][channel] & 0xFE) | bit

    out_img = Image.new('RGB', img.size)
    out_img.putdata([tuple(p) for p in pixels_mut])

    save_kwargs = {}
    if 'exif' in original_info:
        save_kwargs['exif'] = original_info['exif']
    if 'icc_profile' in original_info:
        save_kwargs['icc_profile'] = original_info['icc_profile']

    out_img.save(output_path, **save_kwargs)
    os.utime(output_path, original_times)

    return len(qualifying)


def extract(image_path: str, password: str) -> bytes:
    """
    Extract payload from high-complexity pixels.
    Returns raw (still-encrypted) bytes.
    """
    img    = Image.open(image_path).convert('RGB')
    w, h   = img.size
    pixels = list(img.getdata())

    qualifying = _qualifying_pixels(pixels, w, h, password)

    def read_bits(n_bits: int, start: int) -> list:
        bits = []
        for i in range(n_bits):
            pos     = start + i
            pix_idx = qualifying[pos // 3]
            channel = pos % 3
            bits.append(pixels[pix_idx][channel] & 1)
        return bits

    length_bits  = read_bits(32, 0)
    length       = struct.unpack('<I', _bits_to_bytes(length_bits))[0]

    if length == 0 or length > (len(qualifying) * 3) // 8:
        raise ValueError(
            "No valid adaptive payload found "
            "(wrong password or image contains no hidden data)."
        )

    payload_bits = read_bits(length * 8, 32)
    return _bits_to_bytes(payload_bits)
