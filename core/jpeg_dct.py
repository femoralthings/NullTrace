"""
core/jpeg_dct.py — JPEG DCT (Discrete Cosine Transform) steganography

JPEG compresses images by:
  1. Converting RGB to YCbCr colour space
  2. Dividing the Y (luminance) channel into 8x8 pixel blocks
  3. Applying 2D DCT to each block → 64 frequency coefficients
  4. Quantizing (lossy step) and entropy coding

We hide data by modifying mid-frequency DCT coefficients AFTER quantization.
These frequencies are:
  - Not the DC component (index 0,0) — too visible, too important
  - Not the highest frequencies — quantization zeros them out anyway
  - The mid-range: coefficients at zigzag positions 5-20

Why DCT steg is superior to pixel LSB for JPEG:
  - Pixel LSB doesn't survive JPEG re-saves (quantization destroys it)
  - DCT coefficients ARE the JPEG — modifying them is modifying the format natively
  - Changes in mid-frequency coefficients are masked by the eye's spatial frequency response
  - Statistically: mid-frequency coefficient histograms are hard to distinguish from natural

Implementation uses scipy for DCT/IDCT. We work on the YCbCr Y channel only
(luminance) since the eye is most sensitive to luminance and least to chrominance,
making Y the best hiding channel paradoxically (quantization tables are coarser there).

Note: saving re-encodes the JPEG. Use quality=95+ to minimize coefficient disruption.
"""

import os
import struct
import hashlib
import random
import numpy as np
from pathlib import Path
from PIL import Image

try:
    from scipy.fft import dctn, idctn
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

BLOCK_SIZE   = 8
LENGTH_BYTES = 4

# Zigzag scan order for 8x8 DCT block (standard JPEG order)
ZIGZAG = [
    (0,0),(0,1),(1,0),(2,0),(1,1),(0,2),(0,3),(1,2),
    (2,1),(3,0),(4,0),(3,1),(2,2),(1,3),(0,4),(0,5),
    (1,4),(2,3),(3,2),(4,1),(5,0),(6,0),(5,1),(4,2),
    (3,3),(2,4),(1,5),(0,6),(0,7),(1,6),(2,5),(3,4),
    (4,3),(5,2),(6,1),(7,0),(7,1),(6,2),(5,3),(4,4),
    (3,5),(2,6),(1,7),(2,7),(3,6),(4,5),(5,4),(6,3),
    (7,2),(7,3),(6,4),(5,5),(4,6),(3,7),(4,7),(5,6),
    (6,5),(7,4),(7,5),(6,6),(5,7),(6,7),(7,6),(7,7),
]

# Mid-frequency coefficient positions (skip DC and very high freq)
MID_FREQ_POSITIONS = ZIGZAG[5:20]


def _require_scipy():
    if not SCIPY_AVAILABLE:
        raise ImportError(
            "DCT steganography requires scipy. "
            "Install with: pip install scipy"
        )


def _spread_seed(password: str) -> int:
    h = hashlib.sha256(b"nulltrace-dct-spread:" + password.encode()).digest()
    return int.from_bytes(h, 'big')


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


def _get_blocks(channel: np.ndarray) -> tuple:
    """Divide channel into 8x8 blocks. Returns (blocks list, padded shape)."""
    h, w = channel.shape
    # Pad to multiple of 8
    pad_h = (BLOCK_SIZE - h % BLOCK_SIZE) % BLOCK_SIZE
    pad_w = (BLOCK_SIZE - w % BLOCK_SIZE) % BLOCK_SIZE
    padded = np.pad(channel, ((0, pad_h), (0, pad_w)), mode='edge').astype(float)

    ph, pw = padded.shape
    blocks = []
    positions = []
    for by in range(0, ph, BLOCK_SIZE):
        for bx in range(0, pw, BLOCK_SIZE):
            blocks.append(padded[by:by+BLOCK_SIZE, bx:bx+BLOCK_SIZE])
            positions.append((by, bx))
    return blocks, positions, padded.shape


def capacity(image_path: str) -> int:
    """Return payload capacity in bytes for DCT embedding."""
    _require_scipy()
    img = Image.open(image_path).convert('YCbCr')
    y   = np.array(img)[:, :, 0]
    h, w = y.shape
    n_blocks = ((h + 7) // 8) * ((w + 7) // 8)
    # len(MID_FREQ_POSITIONS) bits per block
    total_bits = n_blocks * len(MID_FREQ_POSITIONS)
    return total_bits // 8 - LENGTH_BYTES


def hide(image_path: str, payload: bytes, password: str,
         output_path: str, quality: int = 95) -> None:
    """
    Embed payload in JPEG DCT mid-frequency coefficients.
    Uses the Y (luminance) channel of YCbCr colour space.
    Re-encodes the JPEG at the specified quality (default 95).
    """
    _require_scipy()
    if Path(image_path).suffix.lower() not in ('.jpg', '.jpeg'):
        raise ValueError("DCT steganography is for JPEG files only.")

    stat = os.stat(image_path)
    original_times = (stat.st_atime, stat.st_mtime)

    img_rgb = Image.open(image_path).convert('RGB')
    img_ycbcr = img_rgb.convert('YCbCr')
    ycbcr = np.array(img_ycbcr, dtype=float)

    y_channel = ycbcr[:, :, 0]
    blocks, positions, padded_shape = _get_blocks(y_channel)

    framed = struct.pack('<I', len(payload)) + payload
    bits   = _bytes_to_bits(framed)

    # PRNG block order
    rng = random.Random(_spread_seed(password))
    block_order = list(range(len(blocks)))
    rng.shuffle(block_order)

    max_bits = len(blocks) * len(MID_FREQ_POSITIONS)
    if len(bits) > max_bits:
        cap = max_bits // 8 - LENGTH_BYTES
        raise ValueError(
            f"Payload too large ({len(payload)} bytes). "
            f"DCT capacity: {cap} bytes."
        )

    bit_idx = 0
    dct_blocks = []

    for orig_idx, block in enumerate(blocks):
        dct_block = dctn(block, norm='ortho')
        dct_blocks.append(dct_block)

    for shuffled_idx in range(len(block_order)):
        if bit_idx >= len(bits):
            break
        block_idx = block_order[shuffled_idx]
        dct_block  = dct_blocks[block_idx]

        for (r, c) in MID_FREQ_POSITIONS:
            if bit_idx >= len(bits):
                break
            coef = dct_block[r, c]
            # Embed in LSB of rounded coefficient
            rounded = round(coef)
            if rounded == 0:
                # Skip zero coefficients — modifying them changes sparsity
                continue
            new_val = (int(rounded) & ~1) | bits[bit_idx]
            dct_block[r, c] = float(new_val)
            bit_idx += 1

    # Reconstruct Y channel
    ph, pw = padded_shape
    new_y = np.zeros((ph, pw), dtype=float)
    for i, (by, bx) in enumerate(positions):
        new_y[by:by+BLOCK_SIZE, bx:bx+BLOCK_SIZE] = idctn(dct_blocks[i], norm='ortho')

    # Crop back to original size
    h, w = y_channel.shape
    new_y = np.clip(new_y[:h, :w], 0, 255)

    ycbcr[:, :, 0] = new_y
    out_ycbcr = Image.fromarray(np.uint8(np.clip(ycbcr, 0, 255)), 'YCbCr')
    out_rgb   = out_ycbcr.convert('RGB')
    out_rgb.save(output_path, 'JPEG', quality=quality, subsampling=0)

    os.utime(output_path, original_times)


def extract(image_path: str, password: str) -> bytes:
    """
    Extract payload from JPEG DCT mid-frequency coefficients.
    Returns raw (still-encrypted) bytes.
    """
    _require_scipy()

    img_ycbcr = Image.open(image_path).convert('YCbCr')
    ycbcr     = np.array(img_ycbcr, dtype=float)
    y_channel = ycbcr[:, :, 0]

    blocks, positions, padded_shape = _get_blocks(y_channel)

    rng = random.Random(_spread_seed(password))
    block_order = list(range(len(blocks)))
    rng.shuffle(block_order)

    dct_blocks = [dctn(block, norm='ortho') for block in blocks]

    def read_bits_dct(n_bits: int, start: int) -> list:
        bits     = []
        bit_pos  = 0
        total    = 0
        for shuffled_idx in range(len(block_order)):
            if total >= start + n_bits:
                break
            block_idx = block_order[shuffled_idx]
            dct_block  = dct_blocks[block_idx]
            for (r, c) in MID_FREQ_POSITIONS:
                coef    = dct_block[r, c]
                rounded = round(coef)
                if rounded == 0:
                    continue
                if total >= start:
                    bits.append(int(rounded) & 1)
                total += 1
                if len(bits) >= n_bits:
                    return bits
        return bits

    # Read length header
    length_bits = read_bits_dct(32, 0)
    if len(length_bits) < 32:
        raise ValueError("Could not read enough DCT coefficients for length header.")

    length = struct.unpack('<I', _bits_to_bytes(length_bits))[0]

    max_cap = (len(blocks) * len(MID_FREQ_POSITIONS)) // 8
    if length == 0 or length > max_cap:
        raise ValueError(
            "No valid DCT payload found "
            "(wrong password or image contains no hidden data)."
        )

    payload_bits = read_bits_dct(length * 8, 32)
    return _bits_to_bytes(payload_bits)
