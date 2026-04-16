"""
core/zip_comment.py — ZIP file comment steganography

The ZIP End of Central Directory record includes a variable-length comment field
supporting up to 65,535 bytes. Most archivers (WinRAR, 7-Zip, Windows Explorer)
display the comment in file info but don't visually flag it as unusual.

The comment field is perfectly preserved through extraction and re-archiving
of the contents — only a complete re-zip from scratch would lose it.

Practical uses:
  - Hiding encrypted data in an otherwise normal-looking archive
  - Dead drop: publicly share a ZIP whose comment contains a payload
  - Exfil: blend payload into what looks like an archive description
"""

import os
import shutil
import zipfile


def capacity() -> int:
    """Maximum payload size for ZIP comment field."""
    return 65535


def hide(zip_path: str, payload: bytes, output_path: str) -> None:
    """
    Write payload to ZIP comment field.
    Copies the original ZIP first; does not modify the archive contents.
    """
    if len(payload) > 65535:
        raise ValueError(
            f"Payload is {len(payload)} bytes. ZIP comment max is 65,535 bytes."
        )

    stat = os.stat(zip_path)
    original_times = (stat.st_atime, stat.st_mtime)

    shutil.copy2(zip_path, output_path)

    # Append comment by rewriting End of Central Directory record
    with zipfile.ZipFile(output_path, 'a') as zf:
        zf.comment = payload

    os.utime(output_path, original_times)


def extract(zip_path: str) -> bytes:
    """
    Extract payload from ZIP comment field.
    Returns raw (still-encrypted) bytes.
    """
    with zipfile.ZipFile(zip_path, 'r') as zf:
        comment = zf.comment

    if not comment:
        raise ValueError("ZIP comment field is empty — no payload found.")

    return comment


def scan(zip_path: str) -> dict:
    """
    Blind scan ZIP comment field.
    Estimates if comment looks like binary/encrypted data vs. plain text.
    """
    result = {
        'detected':      False,
        'comment_bytes': 0,
        'looks_binary':  False,
        'findings':      []
    }

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            comment = zf.comment
            info    = zf.infolist()

        if comment:
            result['detected']      = True
            result['comment_bytes'] = len(comment)

            # Heuristic: what fraction of bytes are printable ASCII?
            printable = sum(1 for b in comment if 32 <= b <= 126)
            ratio     = printable / len(comment)

            if ratio < 0.70:
                result['looks_binary'] = True
                result['findings'].append(
                    f"ZIP comment: {len(comment)} bytes, "
                    f"{ratio:.0%} printable — looks like binary/encrypted data"
                )
            else:
                try:
                    text = comment.decode('utf-8', errors='strict')
                    result['findings'].append(
                        f"ZIP comment ({len(comment)} bytes): \"{text[:120]}\""
                    )
                except UnicodeDecodeError:
                    result['findings'].append(
                        f"ZIP comment: {len(comment)} bytes (non-UTF-8 encoding)"
                    )

        # Also check for unusual file count vs archive size
        if info:
            total_compressed = sum(i.compress_size for i in info)
            zip_size = os.path.getsize(zip_path)
            overhead = zip_size - total_compressed
            if overhead > 65536:
                result['findings'].append(
                    f"Archive overhead ({overhead:,} bytes) larger than expected "
                    f"— possible hidden data outside file entries"
                )

    except zipfile.BadZipFile:
        result['findings'].append("File is not a valid ZIP archive")
    except Exception as e:
        result['findings'].append(f"Error scanning ZIP: {e}")

    return result
