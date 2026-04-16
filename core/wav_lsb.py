"""
core/wav_lsb.py — LSB steganography for WAV audio files

WAV stores uncompressed PCM audio. Each sample is a number (e.g., -32768 to 32767
for 16-bit audio). Flipping the LSB of a sample changes its amplitude by 1 unit —
an ~0.003% deviation that is physically inaudible and below the noise floor of
any playback system.

Same PRNG-spread technique as lsb.py: password-seeded Fisher-Yates shuffle over
all sample indices prevents statistical detection of sequential embedding.

Supports 8-bit (unsigned) and 16-bit (signed little-endian) PCM WAV.
Stereo files: interleaved L/R samples are treated as a flat sample array.
"""

import os
import wave
import struct
import hashlib
import random

LENGTH_BYTES = 4


def _spread_seed(password: str) -> int:
    h = hashlib.sha256(b"nulltrace-wav-spread:" + password.encode('utf-8')).digest()
    return int.from_bytes(h, 'big')


def _bits_to_bytes(bits: list) -> bytes:
    result = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            chunk += [0] * (8 - len(chunk))
        result.append(int(''.join(str(b) for b in chunk), 2))
    return bytes(result)


def capacity(wav_path: str) -> int:
    """Return maximum payload size in bytes for this WAV file."""
    with wave.open(wav_path, 'rb') as w:
        n_samples = w.getnframes() * w.getnchannels()
    return n_samples // 8 - LENGTH_BYTES


def hide(wav_path: str, payload: bytes, password: str, output_path: str) -> None:
    """
    Embed payload into WAV audio sample LSBs using PRNG sample selection.
    Preserves all WAV parameters (channels, framerate, sample width, etc.)
    and restores original timestamps.
    """
    stat = os.stat(wav_path)
    original_times = (stat.st_atime, stat.st_mtime)

    with wave.open(wav_path, 'rb') as w:
        params   = w.getparams()
        n_frames = w.getnframes()
        raw      = w.readframes(n_frames)

    sw = params.sampwidth  # bytes per sample

    if sw not in (1, 2):
        raise ValueError(
            f"Only 8-bit and 16-bit WAV supported. This file is {sw * 8}-bit."
        )

    # Unpack samples into a mutable list
    if sw == 2:
        fmt     = f'<{len(raw) // 2}h'   # signed 16-bit little-endian
        samples = list(struct.unpack(fmt, raw))
    else:
        samples = list(raw)               # unsigned 8-bit

    n_samples = len(samples)
    framed    = struct.pack('<I', len(payload)) + payload

    if len(framed) * 8 > n_samples:
        cap = n_samples // 8 - LENGTH_BYTES
        raise ValueError(
            f"Payload too large ({len(payload)} bytes). "
            f"This WAV holds max {cap} bytes."
        )

    # Convert framed payload to bits
    bits = []
    for byte in framed:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    # PRNG sample order
    rng     = random.Random(_spread_seed(password))
    indices = list(range(n_samples))
    rng.shuffle(indices)

    # Embed: clear LSB of selected sample, set to our bit
    for bit_pos, bit in enumerate(bits):
        idx         = indices[bit_pos]
        samples[idx] = (samples[idx] & ~1) | bit

    # Repack
    if sw == 2:
        raw_out = struct.pack(f'<{len(samples)}h', *samples)
    else:
        raw_out = bytes(samples)

    with wave.open(output_path, 'wb') as w:
        w.setparams(params)
        w.writeframes(raw_out)

    os.utime(output_path, original_times)


def extract(wav_path: str, password: str) -> bytes:
    """
    Extract hidden payload from WAV audio.
    Returns raw (still-encrypted) bytes.
    """
    with wave.open(wav_path, 'rb') as w:
        params   = w.getparams()
        n_frames = w.getnframes()
        raw      = w.readframes(n_frames)

    sw = params.sampwidth
    if sw == 2:
        samples = list(struct.unpack(f'<{len(raw) // 2}h', raw))
    else:
        samples = list(raw)

    n_samples = len(samples)

    rng     = random.Random(_spread_seed(password))
    indices = list(range(n_samples))
    rng.shuffle(indices)

    def read_bits(n_bits: int, start: int) -> list:
        return [samples[indices[start + i]] & 1 for i in range(n_bits)]

    # Read 4-byte length header (32 bits)
    length_bits  = read_bits(32, 0)
    length_bytes = _bits_to_bytes(length_bits)
    length       = struct.unpack('<I', length_bytes)[0]

    if length == 0 or length > n_samples // 8:
        raise ValueError(
            "No valid payload found (wrong password, or audio contains no hidden data)."
        )

    payload_bits = read_bits(length * 8, 32)
    return _bits_to_bytes(payload_bits)
