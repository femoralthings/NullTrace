#!/usr/bin/env python3
"""
NullTrace — Multi-carrier steganography toolkit
Hide encrypted data inside files. Detect hidden data in files.
Leave no fingerprints.

Usage:
  nulltrace hide   --in <file> --msg "text" --key <password> --out <file>
  nulltrace hide   --in <file> --file <payload> --key <password> --out <file>
  nulltrace extract --in <file> --key <password>
  nulltrace extract --in <file> --key <password> --out <extracted>
  nulltrace scan   --in <file>
  nulltrace scan   --in <file> --key <password>
  nulltrace scan   --in <dir>  --recursive

Supported carriers:
  PNG / BMP / TIFF  →  LSB steganography (PRNG-spread)
  JPEG              →  EXIF UserComment field
  WAV               →  Audio sample LSB (PRNG-spread)
  PNG/JPEG/GIF/PDF  →  EOF-append (after IEND / FFD9 / %%EOF)
  TXT/HTML/MD/etc.  →  Zero-width Unicode characters
  ZIP               →  Comment field (65KB max)
  PDF               →  XMP metadata
  Any file (Win)    →  NTFS Alternate Data Streams
"""

import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()

# ── Method auto-detection ────────────────────────────────────────────────────

def _auto_method(suffix: str) -> str:
    """Select the best steganography method for a file extension."""
    s = suffix.lower()
    if s in ('.png', '.bmp', '.tiff', '.tif'):
        return 'lsb'
    if s in ('.jpg', '.jpeg'):
        return 'exif'
    if s == '.wav':
        return 'wav'
    if s == '.zip':
        return 'zip'
    if s == '.pdf':
        return 'pdf'
    if s in ('.txt', '.html', '.htm', '.md', '.xml', '.csv', '.js', '.py'):
        return 'zwc'
    # Fallback — EOF append works on most binary formats
    return 'eof'


METHOD_CHOICES = click.Choice(
    ['auto', 'lsb', 'exif', 'wav', 'eof', 'zwc', 'zip', 'pdf', 'ads'],
    case_sensitive=False
)


# ── CLI group ────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version='1.0.0', prog_name='NullTrace')
def cli():
    """NullTrace — steganography toolkit. Hide and detect data in files."""
    pass


# ── hide ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--in',   'input_file',   required=True,  help='Carrier file')
@click.option('--out',  'output_file',  required=True,  help='Output file (or ADS stream name)')
@click.option('--msg',  'message',      default=None,   help='Text message to hide')
@click.option('--file', 'payload_file', default=None,   help='File to hide (any type)')
@click.option('--key',  'password',     required=True,  help='Encryption password')
@click.option('--method', default='auto', type=METHOD_CHOICES,
              help='Embedding method (default: auto from file extension)')
def hide(input_file, output_file, message, payload_file, password, method):
    """
    Embed encrypted data into a carrier file.

    The payload is encrypted with AES-256-GCM before embedding.
    Use --msg for text or --file to hide any file type inside the carrier.

    \b
    Examples:
      nulltrace hide --in photo.png --msg "meet at 0300" --key s3cr3t --out out.png
      nulltrace hide --in photo.png --file secret.pdf   --key s3cr3t --out out.png
      nulltrace hide --in audio.wav --msg "coordinates" --key s3cr3t --out out.wav
    """
    if not message and not payload_file:
        console.print("[red]Error:[/red] provide --msg <text> or --file <path>")
        sys.exit(1)
    if message and payload_file:
        console.print("[red]Error:[/red] use --msg OR --file, not both")
        sys.exit(1)

    # Assemble raw payload
    if message:
        raw_payload = message.encode('utf-8')
    else:
        try:
            with open(payload_file, 'rb') as f:
                raw_payload = f.read()
        except FileNotFoundError:
            console.print(f"[red]Payload file not found:[/red] {payload_file}")
            sys.exit(1)

    # Encrypt
    from core import crypto
    try:
        encrypted = crypto.encrypt(raw_payload, password)
    except Exception as e:
        console.print(f"[red]Encryption error:[/red] {e}")
        sys.exit(1)

    suffix = Path(input_file).suffix
    if method == 'auto':
        method = _auto_method(suffix)

    console.print(f"  Method:    [cyan]{method.upper()}[/cyan]")
    console.print(f"  Payload:   {len(raw_payload)} bytes → encrypted to {len(encrypted)} bytes")

    try:
        _do_hide(method, input_file, output_file, encrypted, password)
        console.print(f"  Output:    [green]{output_file}[/green]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


def _do_hide(method, input_file, output_file, encrypted, password):
    if method == 'lsb':
        from core.lsb import hide as h, capacity
        cap = capacity(input_file)
        if len(encrypted) > cap:
            raise ValueError(
                f"Payload too large ({len(encrypted)} bytes). "
                f"Image capacity: {cap} bytes."
            )
        h(input_file, encrypted, password, output_file)

    elif method == 'exif':
        from core.jpeg_exif import hide as h
        h(input_file, encrypted, output_file)

    elif method == 'wav':
        from core.wav_lsb import hide as h
        h(input_file, encrypted, password, output_file)

    elif method == 'eof':
        from core.eof_append import hide as h
        h(input_file, encrypted, output_file)

    elif method == 'zwc':
        from core.zero_width import hide as h
        with open(input_file, 'r', encoding='utf-8') as f:
            cover = f.read()
        result = h(cover, encrypted)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result)

    elif method == 'zip':
        from core.zip_comment import hide as h
        h(input_file, encrypted, output_file)

    elif method == 'pdf':
        from core.pdf_meta import hide as h
        h(input_file, encrypted, output_file)

    elif method == 'ads':
        from core.ntfs_ads import hide as h
        # For ADS: output_file is treated as the stream name
        h(input_file, output_file, encrypted)
        console.print(
            f"  Hidden in ADS: [cyan]{input_file}:{output_file}[/cyan]  "
            f"(visible size of host file unchanged)"
        )


# ── extract ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--in',     'input_file',  required=True,  help='File containing hidden data')
@click.option('--key',    'password',    required=True,  help='Decryption password')
@click.option('--out',    'output_file', default=None,   help='Save decrypted payload to file')
@click.option('--method', default='auto', type=METHOD_CHOICES, help='Extraction method')
@click.option('--stream', default=None,  help='ADS stream name (required for --method ads)')
def extract(input_file, password, output_file, method, stream):
    """
    Extract and decrypt hidden data from a carrier file.

    \b
    Examples:
      nulltrace extract --in out.png  --key s3cr3t
      nulltrace extract --in out.png  --key s3cr3t --out recovered.pdf
      nulltrace extract --in doc.txt  --key s3cr3t --method zwc
      nulltrace extract --in host.txt --key s3cr3t --method ads --stream hidden
    """
    from core import crypto

    suffix = Path(input_file).suffix
    if method == 'auto':
        method = _auto_method(suffix)

    try:
        raw = _do_extract(method, input_file, password, stream)
    except Exception as e:
        console.print(f"[red]Extraction failed:[/red] {e}")
        sys.exit(1)

    try:
        plaintext = crypto.decrypt(raw, password)
    except ValueError as e:
        console.print(f"[red]Decryption failed:[/red] {e}")
        sys.exit(1)

    if output_file:
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        console.print(
            f"[green]Payload saved:[/green] {output_file} ({len(plaintext)} bytes)"
        )
    else:
        try:
            text = plaintext.decode('utf-8')
            from rich.panel import Panel
            console.print(Panel(
                f"[green]{text}[/green]",
                title="[bold green]Extracted Message[/bold green]"
            ))
        except UnicodeDecodeError:
            console.print(
                f"[yellow]Binary payload ({len(plaintext)} bytes):[/yellow]\n"
                + plaintext[:128].hex()
                + ('...' if len(plaintext) > 128 else '')
            )


def _do_extract(method, input_file, password, stream):
    if method == 'lsb':
        from core.lsb import extract as x
        return x(input_file, password)
    elif method == 'exif':
        from core.jpeg_exif import extract as x
        return x(input_file)
    elif method == 'wav':
        from core.wav_lsb import extract as x
        return x(input_file, password)
    elif method == 'eof':
        from core.eof_append import extract as x
        return x(input_file)
    elif method == 'zwc':
        from core.zero_width import extract as x
        with open(input_file, 'r', encoding='utf-8') as f:
            return x(f.read())
    elif method == 'zip':
        from core.zip_comment import extract as x
        return x(input_file)
    elif method == 'pdf':
        from core.pdf_meta import extract as x
        return x(input_file)
    elif method == 'ads':
        if not stream:
            raise ValueError("--stream is required for ADS extraction")
        from core.ntfs_ads import extract as x
        return x(input_file, stream)
    else:
        raise ValueError(f"Unknown method: {method}")


# ── scan ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--in',        'target',    required=True, help='File or directory to scan')
@click.option('--key',       'password',  default=None,  help='Optional key — attempt extraction if found')
@click.option('--recursive', '-r',        is_flag=True,  help='Scan directory recursively')
@click.option('--verbose',   '-v',        is_flag=True,  help='Show details for clean files too')
@click.option('--extensions', default=None,
              help='Comma-separated extensions to scan (e.g. ".png,.jpg,.wav")')
def scan(target, password, recursive, verbose, extensions):
    """
    Blind-scan a file (or directory) for steganographic content.

    Runs all applicable detection methods. No password needed to detect —
    the password is only used to attempt extraction if something is found.

    \b
    Examples:
      nulltrace scan --in suspicious.png
      nulltrace scan --in suspicious.png --key s3cr3t
      nulltrace scan --in /captures/ --recursive
      nulltrace scan --in /captures/ --recursive --extensions ".png,.jpg"
    """
    from detector.scan import scan_file, print_report

    target_path = Path(target)
    ext_filter  = None
    if extensions:
        ext_filter = {e.strip().lower() for e in extensions.split(',')}

    if target_path.is_file():
        report = scan_file(str(target_path), password=password, verbose=verbose)
        print_report(report)
        sys.exit(0 if not report['overall_suspicious'] else 1)

    elif target_path.is_dir():
        glob_pattern = '**/*' if recursive else '*'
        all_files    = [f for f in target_path.glob(glob_pattern) if f.is_file()]

        if ext_filter:
            all_files = [f for f in all_files if f.suffix.lower() in ext_filter]

        console.print(f"\n[cyan]Scanning {len(all_files)} files...[/cyan]")
        suspicious_count = 0

        for f in sorted(all_files):
            try:
                report = scan_file(str(f), password=password, verbose=verbose)
                if report['overall_suspicious'] or verbose:
                    print_report(report)
                if report['overall_suspicious']:
                    suspicious_count += 1
            except Exception as e:
                if verbose:
                    console.print(f"[dim]  Skipped {f.name}: {e}[/dim]")

        color = 'red' if suspicious_count else 'green'
        console.print(
            f"\n[bold {color}]Scan complete: "
            f"{suspicious_count}/{len(all_files)} files suspicious[/bold {color}]\n"
        )
        sys.exit(0 if suspicious_count == 0 else 1)

    else:
        console.print(f"[red]Target not found:[/red] {target}")
        sys.exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    cli()
