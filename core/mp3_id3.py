"""
core/mp3_id3.py — MP3 ID3 tag steganography

MP3 files use ID3 tags to store metadata (title, artist, album, etc.).
The COMM (comment) frame supports arbitrary text of any length in any language.
Most music players display only a subset of tags — COMM with a non-standard
description field is rarely shown or inspected.

We use a COMM frame with:
  description = 'NT'  (NullTrace marker, appears as an innocuous field name)
  language    = 'eng'
  text        = hex-encoded encrypted payload

The file's audio data is completely untouched — bit-perfect preservation.
Tag insertion is handled by mutagen which is already in requirements.

Capacity: ID3 comment tags support up to ~16MB. Effectively unlimited
for any realistic encrypted payload.
"""

import os
import shutil
from pathlib import Path

try:
    from mutagen.id3 import ID3, COMM, ID3NoHeaderError
    from mutagen.mp3 import MP3
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False

NT_DESCRIPTION = 'NT'
NT_LANG        = 'eng'


def _require_mutagen():
    if not MUTAGEN_AVAILABLE:
        raise ImportError(
            "MP3 steganography requires mutagen. "
            "Install with: pip install mutagen"
        )


def hide(mp3_path: str, payload: bytes, output_path: str) -> None:
    """
    Embed payload in MP3 COMM (comment) ID3 tag.
    Audio data is untouched — only metadata changes.
    """
    _require_mutagen()
    if Path(mp3_path).suffix.lower() != '.mp3':
        raise ValueError("MP3 ID3 steganography requires an .mp3 file.")

    stat = os.stat(mp3_path)
    original_times = (stat.st_atime, stat.st_mtime)

    shutil.copy2(mp3_path, output_path)

    try:
        tags = ID3(output_path)
    except ID3NoHeaderError:
        tags = ID3()

    # Remove any existing NullTrace COMM tag
    key = f'COMM:{NT_DESCRIPTION}:{NT_LANG}'
    if key in tags:
        del tags[key]

    tags.add(COMM(
        encoding=3,           # UTF-8
        lang=NT_LANG,
        desc=NT_DESCRIPTION,
        text=payload.hex()
    ))

    tags.save(output_path, v2_version=3)
    os.utime(output_path, original_times)


def extract(mp3_path: str) -> bytes:
    """
    Extract payload from MP3 COMM ID3 tag.
    Returns raw (still-encrypted) bytes.
    """
    _require_mutagen()

    try:
        tags = ID3(mp3_path)
    except ID3NoHeaderError:
        raise ValueError("No ID3 tags found in this MP3 file.")

    # Look for our specific COMM frame
    key = f'COMM:{NT_DESCRIPTION}:{NT_LANG}'
    if key not in tags:
        # Try scanning all COMM frames
        for frame_key, frame in tags.items():
            if frame_key.startswith('COMM') and hasattr(frame, 'desc'):
                if frame.desc == NT_DESCRIPTION:
                    try:
                        return bytes.fromhex(str(frame.text[0]))
                    except (ValueError, IndexError):
                        continue
        raise ValueError("No NullTrace payload found in MP3 ID3 tags.")

    frame = tags[key]
    try:
        return bytes.fromhex(str(frame.text[0]))
    except (ValueError, IndexError):
        raise ValueError("MP3 ID3 payload is malformed (not valid hex).")


def scan(mp3_path: str) -> dict:
    """
    Scan MP3 for unusual ID3 tags, large comment fields, and known patterns.
    """
    result = {'detected': False, 'findings': []}

    if not MUTAGEN_AVAILABLE:
        result['findings'].append("mutagen not installed — MP3 scanning unavailable")
        return result

    try:
        tags = ID3(mp3_path)
    except ID3NoHeaderError:
        result['findings'].append("No ID3 tags in file")
        return result
    except Exception as e:
        result['findings'].append(f"Error reading ID3: {e}")
        return result

    # Check all COMM frames
    for key, frame in tags.items():
        if not key.startswith('COMM'):
            continue

        desc = getattr(frame, 'desc', '')
        text = str(frame.text[0]) if frame.text else ''

        if desc == NT_DESCRIPTION:
            result['detected'] = True
            result['findings'].append(
                f"NullTrace ID3 marker found (COMM:{desc}:{getattr(frame, 'lang', '')})"
            )

        # Large comment = suspicious
        if len(text) > 200:
            result['detected'] = True
            result['findings'].append(
                f"Large COMM frame ({len(text)} chars, desc='{desc}')"
            )

        # Hex-only content = likely encoded binary
        if text and all(c in '0123456789abcdefABCDEF' for c in text) and len(text) > 32:
            result['detected'] = True
            result['findings'].append(
                f"COMM frame contains hex-only content ({len(text)//2} apparent bytes)"
            )

    # Check for unusual private frames (PRIV)
    priv_frames = [k for k in tags if k.startswith('PRIV')]
    if priv_frames:
        result['findings'].append(
            f"{len(priv_frames)} PRIV (private) frame(s) found: {priv_frames}"
        )
        result['detected'] = True

    return result
