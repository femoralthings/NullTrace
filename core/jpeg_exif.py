"""
core/jpeg_exif.py — JPEG steganography via EXIF metadata

JPEG uses lossy DCT compression — pixel LSB values don't survive a save/load cycle.
Instead, we hide data in EXIF metadata fields which survive perfectly.

Target field: UserComment (tag 0x9286) — large capacity, rarely inspected.
We use shutil.copy2 + piexif.insert to avoid re-encoding the JPEG entirely,
which would change compression quality and leave a Pillow fingerprint.

The EXIF Software tag is preserved from the original to avoid tool fingerprinting.
"""

import os
import shutil
import piexif

EXIF_TAG_USER_COMMENT  = 0x9286      # Exif.Exif.UserComment
EXIF_TAG_SOFTWARE      = 0x0131      # Exif.0th.Software
NT_MARKER              = b'NTv1:'    # 5-byte NullTrace marker within UserComment
# EXIF UserComment charset prefix must be exactly 8 bytes.
# 8 null bytes = "undefined" encoding (EXIF 2.3 spec, section 4.6.5)
UC_PREFIX              = b'\x00' * 8


def hide(image_path: str, payload: bytes, output_path: str) -> None:
    """
    Embed payload into the JPEG UserComment EXIF field.
    Preserves all other EXIF fields including Software tag.
    Does NOT re-encode JPEG pixel data — zero quality change.
    """
    stat = os.stat(image_path)
    original_times = (stat.st_atime, stat.st_mtime)

    try:
        exif_dict = piexif.load(image_path)
    except Exception:
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}

    # UserComment format: 8-byte charset code + data
    # UC_PREFIX = 8 null bytes = "undefined" charset (EXIF spec requirement)
    user_comment = UC_PREFIX + NT_MARKER + payload
    exif_dict.setdefault('Exif', {})[EXIF_TAG_USER_COMMENT] = user_comment

    exif_bytes = piexif.dump(exif_dict)

    # Copy file then surgically replace EXIF — no pixel re-encoding
    shutil.copy2(image_path, output_path)
    piexif.insert(exif_bytes, output_path)

    os.utime(output_path, original_times)


def extract(image_path: str) -> bytes:
    """
    Extract payload from JPEG UserComment EXIF field.
    Returns raw (still-encrypted) bytes.
    """
    try:
        exif_dict = piexif.load(image_path)
    except Exception:
        raise ValueError("No EXIF data found in this JPEG.")

    user_comment = exif_dict.get('Exif', {}).get(EXIF_TAG_USER_COMMENT, b'')

    if not user_comment:
        raise ValueError("No UserComment field in EXIF.")

    # Strip the 8-byte charset prefix
    content = user_comment[8:] if len(user_comment) >= 8 else user_comment

    if not content.startswith(NT_MARKER):
        raise ValueError("No NullTrace payload found in EXIF UserComment.")

    return content[len(NT_MARKER):]


def strip_exif(image_path: str, output_path: str) -> None:
    """
    Remove ALL EXIF data from a JPEG. Useful for opsec before sending.
    """
    shutil.copy2(image_path, output_path)
    piexif.remove(output_path)


def dump_exif(image_path: str) -> dict:
    """Return all EXIF fields as a dict for inspection/scanning."""
    try:
        return piexif.load(image_path)
    except Exception:
        return {}
