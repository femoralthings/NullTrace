#!/usr/bin/env python3
"""
NullTrace — Multi-carrier steganography toolkit
Hide encrypted data inside files. Detect hidden data in files.
Leave no fingerprints.

Usage:
  nulltrace hide       --in <file> --msg "text" --key <password> --out <file>
  nulltrace hide       --in <file> --file <payload> --key <password> --out <file>
  nulltrace hide-dual  --in <file> --real-msg "secret" --real-key <pw>
                       --decoy-msg "innocent" --decoy-key <pw> --out <file>
  nulltrace extract    --in <file> --key <password>
  nulltrace extract    --in <file> --key <password> --out <extracted>
  nulltrace extract-real --in <file> --key <password>
  nulltrace scan       --in <file>
  nulltrace scan       --in <file> --key <password>
  nulltrace scan       --in <dir>  --recursive --csv results.csv

Supported methods:
  auto / lsb / alpha / adaptive / dct / exif
  wav / eof / zwc / zip / pdf / ads / docx / mp3
"""

import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()


# ── Method auto-detection ─────────────────────────────────────────────────────

def _auto_method(suffix: str) -> str:
    """Select the best steganography method for a file extension."""
    s = suffix.lower()
    if s in ('.png', '.bmp', '.tiff', '.tif'):
        return 'lsb'
    if s in ('.jpg', '.jpeg'):
        return 'exif'
    if s == '.wav':
        return 'wav'
    if s == '.mp3':
        return 'mp3'
    if s == '.zip':
        return 'zip'
    if s == '.pdf':
        return 'pdf'
    if s == '.docx':
        return 'docx'
    if s in ('.txt', '.html', '.htm', '.md', '.xml', '.csv', '.js', '.py'):
        return 'zwc'
    return 'eof'


METHOD_CHOICES = click.Choice(
    ['auto', 'lsb', 'alpha', 'adaptive', 'dct',
     'exif', 'wav', 'eof', 'zwc', 'zip', 'pdf', 'ads', 'docx', 'mp3'],
    case_sensitive=False
)

KEYFILE_OPTION = click.option(
    '--keyfile', default=None,
    help='Path to key file (second factor — required for decryption if used during hide)'
)


# ── CLI group ─────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version='2.0.0', prog_name='NullTrace')
def cli():
    """NullTrace — steganography toolkit. Hide and detect data in files."""
    pass


# ── hide ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--in',      'input_file',   required=True,  help='Carrier file')
@click.option('--out',     'output_file',  required=True,  help='Output file')
@click.option('--msg',     'message',      default=None,   help='Text message to hide')
@click.option('--file',    'payload_file', default=None,   help='File to hide (any type)')
@click.option('--key',     'password',     required=True,  help='Encryption password')
@KEYFILE_OPTION
@click.option('--method',  default='auto', type=METHOD_CHOICES,
              help='Embedding method (default: auto from file extension)')
@click.option('--quality', default=95, show_default=True,
              help='JPEG re-encode quality for DCT method (1-100)')
def hide(input_file, output_file, message, payload_file,
         password, keyfile, method, quality):
    """
    Embed encrypted data into a carrier file.

    The payload is encrypted with AES-256-GCM before embedding.
    Use --msg for text or --file to hide any file type inside the carrier.
    Use --keyfile to require a physical file in addition to the password.

    \b
    Examples:
      nulltrace hide --in photo.png --msg "meet at 0300" --key s3cr3t --out out.png
      nulltrace hide --in photo.png --file secret.pdf --key s3cr3t --out out.png
      nulltrace hide --in photo.jpg --msg "text" --key s3cr3t --method dct --out out.jpg
      nulltrace hide --in audio.wav --msg "coords" --key s3cr3t --out out.wav
      nulltrace hide --in photo.png --msg "hi" --key s3cr3t --keyfile /path/to/key.bin --out out.png
    """
    if not message and not payload_file:
        console.print("[red]Error:[/red] provide --msg <text> or --file <path>")
        sys.exit(1)
    if message and payload_file:
        console.print("[red]Error:[/red] use --msg OR --file, not both")
        sys.exit(1)

    if message:
        raw_payload = message.encode('utf-8')
    else:
        try:
            with open(payload_file, 'rb') as f:
                raw_payload = f.read()
        except FileNotFoundError:
            console.print(f"[red]Payload file not found:[/red] {payload_file}")
            sys.exit(1)

    kf_bytes = _load_keyfile(keyfile)

    from core import crypto
    try:
        encrypted = crypto.encrypt(raw_payload, password, kf_bytes)
    except Exception as e:
        console.print(f"[red]Encryption error:[/red] {e}")
        sys.exit(1)

    suffix = Path(input_file).suffix
    if method == 'auto':
        method = _auto_method(suffix)

    console.print(f"  Method:  [cyan]{method.upper()}[/cyan]")
    console.print(f"  Payload: {len(raw_payload)} B  →  encrypted {len(encrypted)} B")
    if kf_bytes:
        console.print(f"  Keyfile: [yellow]{keyfile}[/yellow] (required for extraction)")

    try:
        _do_hide(method, input_file, output_file, encrypted, password, quality)
        console.print(f"  Output:  [green]{output_file}[/green]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


def _do_hide(method, input_file, output_file, encrypted, password, quality=95):
    if method == 'lsb':
        from core.lsb import hide as h, capacity
        cap = capacity(input_file)
        if len(encrypted) > cap:
            raise ValueError(
                f"Payload too large ({len(encrypted)} bytes). "
                f"Image capacity: {cap} bytes."
            )
        h(input_file, encrypted, password, output_file)

    elif method == 'alpha':
        from core.alpha_lsb import hide as h, capacity
        cap = capacity(input_file)
        if len(encrypted) > cap:
            raise ValueError(
                f"Payload too large ({len(encrypted)} bytes). "
                f"Alpha channel capacity: {cap} bytes."
            )
        h(input_file, encrypted, password, output_file)

    elif method == 'adaptive':
        from core.adaptive_lsb import hide as h, capacity
        cap = capacity(input_file)
        if len(encrypted) > cap:
            raise ValueError(
                f"Payload too large ({len(encrypted)} bytes). "
                f"Adaptive LSB capacity: {cap} bytes."
            )
        h(input_file, encrypted, password, output_file)

    elif method == 'dct':
        from core.jpeg_dct import hide as h
        h(input_file, encrypted, password, output_file, quality=quality)

    elif method == 'exif':
        from core.jpeg_exif import hide as h
        h(input_file, encrypted, output_file)

    elif method == 'wav':
        from core.wav_lsb import hide as h
        h(input_file, encrypted, password, output_file)

    elif method == 'mp3':
        from core.mp3_id3 import hide as h
        h(input_file, encrypted, output_file)

    elif method == 'docx':
        from core.docx_hidden import hide as h
        h(input_file, encrypted, output_file)

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
        h(input_file, output_file, encrypted)

    else:
        raise ValueError(f"Unknown method: {method}")


# ── hide-dual ────────────────────────────────────────────────────────────────

@cli.command('hide-dual')
@click.option('--in',        'input_file',   required=True, help='Carrier PNG/BMP/TIFF')
@click.option('--out',       'output_file',  required=True, help='Output file')
@click.option('--real-msg',  'real_msg',     default=None,  help='Real (secret) text payload')
@click.option('--real-file', 'real_file',    default=None,  help='Real (secret) file payload')
@click.option('--real-key',  'real_key',     required=True, help='Password for real payload')
@click.option('--decoy-msg', 'decoy_msg',    default=None,  help='Decoy (innocent) text payload')
@click.option('--decoy-file','decoy_file',   default=None,  help='Decoy (innocent) file payload')
@click.option('--decoy-key', 'decoy_key',    required=True, help='Password for decoy payload')
def hide_dual(input_file, output_file,
              real_msg, real_file, real_key,
              decoy_msg, decoy_file, decoy_key):
    """
    Embed TWO independent payloads for plausible deniability.

    Decoy → bit 0 (LSB) extracted with decoy password (the one you reveal under pressure)
    Real  → bit 1 (2nd bit) extracted with real password (the actual secret)

    Neither password reveals the other payload exists.

    \b
    Example:
      nulltrace hide-dual --in photo.png --out out.png \\
        --real-msg  "target is X" --real-key  s3cr3t \\
        --decoy-msg "grocery list" --decoy-key openme
    """
    from core import crypto

    # Assemble real payload
    if real_msg:
        real_raw = real_msg.encode('utf-8')
    elif real_file:
        with open(real_file, 'rb') as f:
            real_raw = f.read()
    else:
        console.print("[red]Error:[/red] provide --real-msg or --real-file")
        sys.exit(1)

    # Assemble decoy payload
    if decoy_msg:
        decoy_raw = decoy_msg.encode('utf-8')
    elif decoy_file:
        with open(decoy_file, 'rb') as f:
            decoy_raw = f.read()
    else:
        console.print("[red]Error:[/red] provide --decoy-msg or --decoy-file")
        sys.exit(1)

    real_enc  = crypto.encrypt(real_raw,  real_key)
    decoy_enc = crypto.encrypt(decoy_raw, decoy_key)

    from core.lsb import hide_dual as h
    try:
        h(input_file,
          real_payload=real_enc,   real_password=real_key,
          decoy_payload=decoy_enc, decoy_password=decoy_key,
          output_path=output_file)
        console.print(
            f"  [green]Dual embed complete:[/green] {output_file}\n"
            f"  Decoy ({len(decoy_raw)} B) → key: [yellow]{decoy_key}[/yellow]\n"
            f"  Real  ({len(real_raw)}  B) → key: [red]<redacted>[/red]"
        )
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ── extract ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--in',      'input_file',  required=True,  help='File containing hidden data')
@click.option('--key',     'password',    required=True,  help='Decryption password')
@click.option('--out',     'output_file', default=None,   help='Save decrypted payload to file')
@KEYFILE_OPTION
@click.option('--method',  default='auto', type=METHOD_CHOICES, help='Extraction method')
@click.option('--stream',  default=None,  help='ADS stream name (for --method ads)')
def extract(input_file, password, output_file, keyfile, method, stream):
    """
    Extract and decrypt hidden data from a carrier file.

    \b
    Examples:
      nulltrace extract --in out.png  --key s3cr3t
      nulltrace extract --in out.png  --key s3cr3t --out recovered.pdf
      nulltrace extract --in doc.txt  --key s3cr3t --method zwc
      nulltrace extract --in host.txt --key s3cr3t --method ads --stream hidden
      nulltrace extract --in out.jpg  --key s3cr3t --method dct
    """
    from core import crypto

    kf_bytes = _load_keyfile(keyfile)

    suffix = Path(input_file).suffix
    if method == 'auto':
        method = _auto_method(suffix)

    try:
        raw = _do_extract(method, input_file, password, stream)
    except Exception as e:
        console.print(f"[red]Extraction failed:[/red] {e}")
        sys.exit(1)

    try:
        plaintext = crypto.decrypt(raw, password, kf_bytes)
    except ValueError as e:
        console.print(f"[red]Decryption failed:[/red] {e}")
        sys.exit(1)

    _output_payload(plaintext, output_file, method)


def _do_extract(method, input_file, password, stream):
    if method == 'lsb':
        from core.lsb import extract as x
        return x(input_file, password)
    elif method == 'alpha':
        from core.alpha_lsb import extract as x
        return x(input_file, password)
    elif method == 'adaptive':
        from core.adaptive_lsb import extract as x
        return x(input_file, password)
    elif method == 'dct':
        from core.jpeg_dct import extract as x
        return x(input_file, password)
    elif method == 'exif':
        from core.jpeg_exif import extract as x
        return x(input_file)
    elif method == 'wav':
        from core.wav_lsb import extract as x
        return x(input_file, password)
    elif method == 'mp3':
        from core.mp3_id3 import extract as x
        return x(input_file)
    elif method == 'docx':
        from core.docx_hidden import extract as x
        return x(input_file)
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


# ── extract-real ──────────────────────────────────────────────────────────────

@cli.command('extract-real')
@click.option('--in',   'input_file',  required=True, help='Dual-embedded image')
@click.option('--key',  'password',    required=True, help='Real payload password')
@click.option('--out',  'output_file', default=None,  help='Save decrypted payload to file')
@KEYFILE_OPTION
def extract_real(input_file, password, output_file, keyfile):
    """
    Extract the REAL payload from a dual-embedded image (plausible deniability).

    Reads from bit 1 (2nd-least-significant bit) of PRNG-selected pixels.
    The decoy password + extract command will reveal only the innocent payload.

    \b
    Example:
      nulltrace extract-real --in out.png --key s3cr3t
    """
    from core import crypto
    from core.lsb import extract_real as x

    kf_bytes = _load_keyfile(keyfile)

    try:
        raw = x(input_file, password)
    except Exception as e:
        console.print(f"[red]Extraction failed:[/red] {e}")
        sys.exit(1)

    try:
        plaintext = crypto.decrypt(raw, password, kf_bytes)
    except ValueError as e:
        console.print(f"[red]Decryption failed:[/red] {e}")
        sys.exit(1)

    _output_payload(plaintext, output_file, 'Real (dual-plane)')


# ── scan ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--in',        'target',    required=True, help='File or directory to scan')
@click.option('--key',       'password',  default=None,  help='Optional key — attempt extraction if found')
@KEYFILE_OPTION
@click.option('--recursive', '-r',        is_flag=True,  help='Scan directory recursively')
@click.option('--verbose',   '-v',        is_flag=True,  help='Show details for clean files too')
@click.option('--extensions', default=None,
              help='Comma-separated extensions to scan (e.g. ".png,.jpg,.wav")')
@click.option('--csv', 'csv_output', default=None,
              help='Export findings to a CSV file (e.g. results.csv)')
def scan(target, password, keyfile, recursive, verbose, extensions, csv_output):
    """
    Blind-scan a file (or directory) for steganographic content.

    Runs all applicable detection methods — chi-square, RS analysis,
    alpha channel analysis, EOF-append, EXIF, DOCX, MP3, and more.
    No password needed to detect. Password enables extraction attempt.

    \b
    Examples:
      nulltrace scan --in suspicious.png
      nulltrace scan --in suspicious.png --key s3cr3t
      nulltrace scan --in /captures/ --recursive
      nulltrace scan --in /captures/ --recursive --csv results.csv
      nulltrace scan --in /captures/ --recursive --extensions ".png,.jpg"
    """
    from detector.scan import scan_file, print_report, export_csv

    target_path = Path(target)
    ext_filter  = None
    kf_bytes    = _load_keyfile(keyfile)

    if extensions:
        ext_filter = {e.strip().lower() for e in extensions.split(',')}

    all_reports = []

    if target_path.is_file():
        report = scan_file(str(target_path), password=password,
                           keyfile=kf_bytes, verbose=verbose)
        print_report(report)
        all_reports.append(report)
        if csv_output:
            export_csv(all_reports, csv_output)
            console.print(f"[green]CSV exported:[/green] {csv_output}")
        sys.exit(0 if not report['overall_suspicious'] else 1)

    elif target_path.is_dir():
        glob_pattern = '**/*' if recursive else '*'
        all_files = [f for f in target_path.glob(glob_pattern) if f.is_file()]

        if ext_filter:
            all_files = [f for f in all_files if f.suffix.lower() in ext_filter]

        console.print(f"\n[cyan]Scanning {len(all_files)} files...[/cyan]")
        suspicious_count = 0

        for f in sorted(all_files):
            try:
                report = scan_file(str(f), password=password,
                                   keyfile=kf_bytes, verbose=verbose)
                all_reports.append(report)
                if report['overall_suspicious'] or verbose:
                    print_report(report)
                if report['overall_suspicious']:
                    suspicious_count += 1
            except Exception as e:
                if verbose:
                    console.print(f"[dim]  Skipped {f.name}: {e}[/dim]")

        if csv_output:
            export_csv(all_reports, csv_output)
            console.print(f"[green]CSV exported:[/green] {csv_output}")

        color = 'red' if suspicious_count else 'green'
        console.print(
            f"\n[bold {color}]Scan complete: "
            f"{suspicious_count}/{len(all_files)} files suspicious[/bold {color}]\n"
        )
        sys.exit(0 if suspicious_count == 0 else 1)

    else:
        console.print(f"[red]Target not found:[/red] {target}")
        sys.exit(1)


# ── capacity ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--in',     'input_file', required=True, help='Carrier file to check')
@click.option('--method', default='auto', type=METHOD_CHOICES,
              help='Embedding method to check capacity for')
def capacity(input_file, method):
    """Show the maximum payload capacity for a carrier file and method."""
    suffix = Path(input_file).suffix
    if method == 'auto':
        method = _auto_method(suffix)

    try:
        cap = _get_capacity(method, input_file)
        console.print(
            f"  [cyan]{method.upper()}[/cyan] capacity for [bold]{input_file}[/bold]: "
            f"[green]{cap:,} bytes[/green] ({cap / 1024:.1f} KB)"
        )
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


def _get_capacity(method, input_file):
    if method == 'lsb':
        from core.lsb import capacity as c
        return c(input_file)
    elif method == 'alpha':
        from core.alpha_lsb import capacity as c
        return c(input_file)
    elif method == 'adaptive':
        from core.adaptive_lsb import capacity as c
        return c(input_file)
    elif method == 'dct':
        from core.jpeg_dct import capacity as c
        return c(input_file)
    elif method == 'mp3':
        return 16 * 1024 * 1024  # ID3 COMM limit ~16MB
    elif method in ('exif', 'docx', 'zip', 'pdf', 'eof', 'zwc', 'ads'):
        return 65535  # practical limit varies; show nominal
    else:
        raise ValueError(f"Capacity check not supported for method '{method}'")


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _load_keyfile(keyfile_path):
    """Load key file bytes, or return None if no path given."""
    if not keyfile_path:
        return None
    try:
        with open(keyfile_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        console.print(f"[red]Key file not found:[/red] {keyfile_path}")
        sys.exit(1)


def _output_payload(plaintext: bytes, output_file, method: str):
    """Write or display decrypted payload."""
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
                title=f"[bold green]Extracted Message — {method} ({len(plaintext)} B)[/bold green]"
            ))
        except UnicodeDecodeError:
            console.print(
                f"[yellow]Binary payload ({len(plaintext)} bytes):[/yellow]\n"
                + plaintext[:128].hex()
                + ('...' if len(plaintext) > 128 else '')
            )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    cli()
