"""
detector/signatures.py — Known steganography tool signature database

When investigators find a suspicious file, the first question is:
"Did a known tool do this?" Tool signatures let us answer that
without a password or brute force — just pattern matching.

Covers: StegHide, OpenStego, SilentEye, Camouflage, Outguess, F5,
        SNOW/whitespace stego, MP3Stego, and more.

Each signature includes confidence level and what to look for.
"""

from pathlib import Path

# ── Byte sequence signatures ─────────────────────────────────────────────────

BYTE_SIGNATURES = [
    {
        'tool':        'Camouflage',
        'pattern':     b'Steganography',
        'confidence':  'high',
        'description': 'Camouflage appends its name after EOF'
    },
    {
        'tool':        'OpenStego',
        'pattern':     b'OpenStego',
        'confidence':  'high',
        'description': 'OpenStego PNG comment chunk'
    },
    {
        'tool':        'Invisible Secrets',
        'pattern':     b'InvisibleSecrets',
        'confidence':  'high',
        'description': 'Invisible Secrets marker'
    },
    {
        'tool':        'Hide In Picture',
        'pattern':     b'HideInPicture',
        'confidence':  'high',
        'description': 'Hide In Picture marker'
    },
    {
        'tool':        'StegoStick',
        'pattern':     b'StegoStick',
        'confidence':  'high',
        'description': 'StegoStick marker in file'
    },
    {
        'tool':        'NullTrace',
        'pattern':     b'\x4e\x54\x45\x4f\x46',  # NTEOF
        'confidence':  'certain',
        'description': 'NullTrace EOF-append marker'
    },
]

# ── EXIF Software tag signatures ─────────────────────────────────────────────

EXIF_SOFTWARE_SIGS = [
    'SilentEye',
    'StegHide',
    'OpenStego',
    'Invisible Secrets',
    'Hide In Picture',
    'Camera Shy',
    'PGSteg',
    'StegSpy',
    'Steganos',
    'SecurEngine',
]

# ── PNG chunk signatures ──────────────────────────────────────────────────────

PNG_SUSPICIOUS_CHUNKS = {
    b'stEG',    # some tools use custom chunks
    b'hiDe',
    b'seKr',
}

# ── JPEG markers used by specific tools ───────────────────────────────────────
# StegHide uses the JPEG comment marker (FF FE) in a specific way
JPEG_STEGHIDE_COMMENT_PREFIX = b'\xff\xfe\x00'

# ── Whitespace steganography patterns ────────────────────────────────────────
# SNOW hides data in trailing whitespace (spaces/tabs) at end of lines
SNOW_MIN_TRAILING_LINES = 4


def check_signatures(file_path: str, file_data: bytes, exif_data: dict = None) -> list:
    """
    Run all signature checks against a file.

    Args:
        file_path:  Path to the file being scanned
        file_data:  Raw bytes of the file
        exif_data:  Parsed EXIF dict (from piexif.load) if available

    Returns:
        List of finding dicts: {'tool', 'confidence', 'detail'}
    """
    findings  = []
    suffix    = Path(file_path).suffix.lower()

    # --- Byte sequence scan ---
    for sig in BYTE_SIGNATURES:
        if sig['pattern'] in file_data:
            findings.append({
                'tool':       sig['tool'],
                'confidence': sig['confidence'],
                'detail':     sig['description'],
            })

    # --- EXIF Software tag ---
    if exif_data:
        sw_raw = exif_data.get('0th', {}).get(0x0131, b'')
        software = sw_raw.decode('utf-8', errors='ignore') if isinstance(sw_raw, bytes) else str(sw_raw)
        for known_tool in EXIF_SOFTWARE_SIGS:
            if known_tool.lower() in software.lower():
                findings.append({
                    'tool':       known_tool,
                    'confidence': 'high',
                    'detail':     f'EXIF Software tag: "{software.strip()}"',
                })

        # Also check UserComment for NullTrace marker
        uc = exif_data.get('Exif', {}).get(0x9286, b'')
        if isinstance(uc, bytes) and b'NTv1:' in uc:
            findings.append({
                'tool':       'NullTrace',
                'confidence': 'certain',
                'detail':     'NullTrace marker in EXIF UserComment',
            })

    # --- PNG custom chunks ---
    if suffix == '.png':
        for chunk_type in PNG_SUSPICIOUS_CHUNKS:
            if chunk_type in file_data:
                findings.append({
                    'tool':       'Unknown (custom PNG chunk)',
                    'confidence': 'medium',
                    'detail':     f'Suspicious PNG chunk type: {chunk_type!r}',
                })

    # --- StegHide JPEG comment ---
    if suffix in ('.jpg', '.jpeg'):
        if JPEG_STEGHIDE_COMMENT_PREFIX in file_data:
            findings.append({
                'tool':       'StegHide',
                'confidence': 'medium',
                'detail':     'JPEG comment marker pattern consistent with StegHide',
            })

    # --- SNOW / whitespace steganography ---
    try:
        text_lines = file_data.decode('utf-8', errors='ignore').splitlines()
        trailing_count = sum(
            1 for line in text_lines if line.endswith((' ', '\t'))
        )
        tab_only_trailing = sum(
            1 for line in text_lines if line != line.rstrip('\t')
        )
        if trailing_count >= SNOW_MIN_TRAILING_LINES:
            findings.append({
                'tool':       'SNOW (whitespace stego)',
                'confidence': 'medium' if trailing_count >= 10 else 'low',
                'detail':     f'{trailing_count} lines with trailing whitespace '
                              f'({tab_only_trailing} tab-trailing) — possible SNOW encoding',
            })
    except Exception:
        pass

    return findings
