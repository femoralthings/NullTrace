"""
core/ntfs_ads.py — NTFS Alternate Data Streams (ADS) steganography

NTFS (Windows default filesystem) allows every file to have multiple named
data streams. The default stream (the one you see) is called ::$DATA.
Any file can have additional streams: file.txt:hidden — completely invisible
in Windows Explorer, file managers, and most security tools.

Properties of ADS:
  - The host file's reported size does NOT include ADS size
  - ADS are invisible to `dir`, `ls`, File Explorer, Task Manager
  - ADS are preserved by NTFS copy but NOT by FAT/exFAT copy
    (copying to USB = ADS silently lost — exfil detection gap)
  - Deleted when the host file is deleted
  - Visible via: `dir /r`, Sysinternals Streams.exe, `Get-Item -Stream *`

Real-world uses:
  - Malware persistence (hide payload in ADS of a legit system file)
  - Data exfil staging (store sensitive data in an ADS, copy host file normally)
  - Windows marks downloaded files with Zone.Identifier ADS — NullTrace reads this

Windows-only. Returns informative errors on non-NTFS/non-Windows systems.
"""

import os
import subprocess
from pathlib import Path


def _require_windows():
    if os.name != 'nt':
        raise OSError("NTFS Alternate Data Streams require Windows with NTFS filesystem.")


def hide(host_file: str, stream_name: str, payload: bytes) -> None:
    """
    Write payload to host_file:stream_name.
    The host file must already exist. Its visible size does not change.

    Args:
        host_file:   Path to the existing host file
        stream_name: Name for the hidden stream (e.g., 'config', 'backup')
        payload:     Bytes to hide
    """
    _require_windows()

    if not Path(host_file).exists():
        raise FileNotFoundError(f"Host file not found: {host_file}")

    if ':' in stream_name:
        raise ValueError("stream_name cannot contain ':' character.")

    ads_path = f"{host_file}:{stream_name}"
    with open(ads_path, 'wb') as f:
        f.write(payload)


def extract(host_file: str, stream_name: str) -> bytes:
    """
    Read bytes from host_file:stream_name.
    Returns raw (still-encrypted) bytes.
    """
    _require_windows()

    ads_path = f"{host_file}:{stream_name}"
    try:
        with open(ads_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        raise ValueError(
            f"Stream '{stream_name}' not found on '{host_file}'. "
            f"Use list_streams() to see what streams exist."
        )


def list_streams(host_file: str) -> list:
    """
    List all alternate data streams on a file.
    Returns list of stream name strings (excluding the default ::$DATA stream).
    Uses PowerShell Get-Item -Stream * for reliable parsing on all Windows versions.
    """
    _require_windows()

    try:
        ps_cmd = (
            f'Get-Item -LiteralPath "{host_file}" -Stream * '
            f'| Select-Object -ExpandProperty Stream'
        )
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True,
            text=True,
            timeout=15
        )
        streams = []
        for line in result.stdout.splitlines():
            name = line.strip()
            # Skip the default data stream and empty lines
            if name and name != ':$DATA' and name != '':
                streams.append(name)
        return streams
    except Exception:
        return []


def delete_stream(host_file: str, stream_name: str) -> None:
    """Delete a specific alternate data stream."""
    _require_windows()

    ads_path = f"{host_file}:{stream_name}"
    try:
        os.remove(ads_path)
    except FileNotFoundError:
        raise ValueError(f"Stream '{stream_name}' not found on '{host_file}'.")


def scan(host_file: str) -> dict:
    """
    Scan a file for all alternate data streams.
    Also reads Zone.Identifier if present (marks downloaded files).
    """
    result = {
        'detected':        False,
        'streams':         [],
        'zone_identifier': None,
        'findings':        []
    }

    if os.name != 'nt':
        result['findings'].append("ADS scanning requires Windows/NTFS")
        return result

    if not Path(host_file).exists():
        result['findings'].append(f"File not found: {host_file}")
        return result

    streams = list_streams(host_file)

    if streams:
        result['detected'] = True
        result['streams']  = streams
        result['findings'].append(
            f"Found {len(streams)} ADS: {', '.join(streams)}"
        )

    # Zone.Identifier tells us if the file was downloaded from the internet
    # Zone values: 0=Local, 1=Intranet, 2=Trusted, 3=Internet, 4=Restricted
    try:
        with open(f"{host_file}:Zone.Identifier", 'r', errors='ignore') as f:
            zone_data = f.read().strip()
        result['zone_identifier'] = zone_data
        result['findings'].append(f"Zone.Identifier: {zone_data!r} (file downloaded from internet)")
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return result
