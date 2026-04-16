"""
core/eof_append.py — EOF-append steganography

Many file formats define explicit end markers. Data written AFTER these markers
is ignored by all standard viewers, players, and parsers — but can be read
programmatically with a simple byte scan.

This technique is widely used in:
  - Malware payload delivery (dropper hides shellcode after a JPEG)
  - CTF challenges (flag hidden after PNG IEND chunk)
  - Real espionage (data hidden in media sent via email)

NullTrace appends: [original file][NTEOF marker][4-byte length][payload]

The NTEOF marker lets us find and extract cleanly. Without the marker,
a scanner sees only "extra bytes after EOF" — can't confirm it's NullTrace
or read the payload without the encryption key.
"""

import os
import struct
from pathlib import Path

# NullTrace EOF marker — 5 bytes, looks like arbitrary binary, not a string
NT_EOF_MARKER = b'\x4e\x54\x45\x4f\x46'   # 'NTEOF' in ASCII

# End-of-file markers for each format
# We use rfind() to locate the LAST occurrence (handles concatenated/corrupted files)
EOF_MARKERS = {
    '.png':  b'\x49\x45\x4e\x44\xae\x42\x60\x82',  # PNG: IEND chunk CRC
    '.jpg':  b'\xff\xd9',                              # JPEG: EOI marker
    '.jpeg': b'\xff\xd9',
    '.gif':  b'\x3b',                                  # GIF: trailer byte
    '.bmp':  None,                                     # BMP: no EOF marker, append at true end
    '.pdf':  b'%%EOF',                                 # PDF: %%EOF string
    '.mp3':  None,                                     # MP3: append at end
    '.wav':  None,                                     # WAV: append at end
}

SUPPORTED = set(EOF_MARKERS.keys())


def hide(file_path: str, payload: bytes, output_path: str) -> None:
    """
    Append payload after the file's EOF marker (or at end for formats without one).
    Wire format appended: [NT_EOF_MARKER][uint32 length LE][payload bytes]
    """
    suffix = Path(file_path).suffix.lower()
    if suffix not in SUPPORTED:
        raise ValueError(
            f"EOF append not supported for '{suffix}'. "
            f"Supported: {', '.join(sorted(SUPPORTED))}"
        )

    stat = os.stat(file_path)
    original_times = (stat.st_atime, stat.st_mtime)

    with open(file_path, 'rb') as f:
        original_data = f.read()

    marker = EOF_MARKERS[suffix]
    if marker and marker not in original_data:
        raise ValueError(
            f"EOF marker not found in '{file_path}' — file may be corrupted."
        )

    appended = (
        original_data
        + NT_EOF_MARKER
        + struct.pack('<I', len(payload))
        + payload
    )

    with open(output_path, 'wb') as f:
        f.write(appended)

    os.utime(output_path, original_times)


def extract(file_path: str) -> bytes:
    """
    Extract NullTrace payload appended after the EOF marker.
    Returns raw bytes (still encrypted — caller passes through crypto.decrypt).
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    idx = data.rfind(NT_EOF_MARKER)
    if idx == -1:
        raise ValueError("No NullTrace EOF payload found in this file.")

    offset = idx + len(NT_EOF_MARKER)
    if len(data) < offset + 4:
        raise ValueError("Payload length header is truncated — file may be corrupted.")

    length  = struct.unpack('<I', data[offset:offset + 4])[0]
    payload = data[offset + 4 : offset + 4 + length]

    if len(payload) != length:
        raise ValueError(f"Payload truncated: expected {length} bytes, got {len(payload)}.")

    return payload


def scan(file_path: str) -> dict:
    """
    Blind scan: detect any data after the EOF marker without needing a key.
    Reports extra bytes, whether a NullTrace header is present, and size.
    """
    suffix = Path(file_path).suffix.lower()
    result = {
        'detected':         False,
        'extra_bytes':      0,
        'nulltrace_marker': False,
        'findings':         []
    }

    if suffix not in EOF_MARKERS:
        result['findings'].append(f"EOF scan not applicable to {suffix}")
        return result

    with open(file_path, 'rb') as f:
        data = f.read()

    marker = EOF_MARKERS[suffix]

    if marker:
        last_pos = data.rfind(marker)
        if last_pos != -1:
            tail = data[last_pos + len(marker):]
            if tail:
                result['detected']    = True
                result['extra_bytes'] = len(tail)
                result['findings'].append(
                    f"{len(tail)} bytes found after EOF marker "
                    f"({marker.hex()}) at offset {last_pos}"
                )
                if tail.startswith(NT_EOF_MARKER):
                    result['nulltrace_marker'] = True
                    result['findings'].append("NullTrace NTEOF marker present — encrypted payload likely")
    else:
        # Formats without a defined EOF marker: check if file is larger than expected
        # For BMP: calculate expected size from header
        if suffix == '.bmp' and len(data) >= 6:
            declared_size = struct.unpack('<I', data[2:6])[0]
            actual_size   = len(data)
            if actual_size > declared_size:
                result['detected']    = True
                result['extra_bytes'] = actual_size - declared_size
                result['findings'].append(
                    f"BMP file is {actual_size - declared_size} bytes larger than header declares"
                )
                tail = data[declared_size:]
                if tail.startswith(NT_EOF_MARKER):
                    result['nulltrace_marker'] = True
                    result['findings'].append("NullTrace NTEOF marker present")

    return result
