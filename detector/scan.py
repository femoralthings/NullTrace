"""
detector/scan.py — NullTrace multi-vector blind scanner

Drop any file in. The scanner runs every applicable detection method:
  - Statistical LSB analysis (chi-square + LSB histogram)
  - RS (Regular-Singular) analysis — strongest blind LSB detector
  - Alpha channel LSB distribution analysis
  - JPEG DCT coefficient anomaly detection
  - EOF-append detection
  - Zero-width character scan
  - EXIF metadata anomalies
  - ZIP comment field
  - PDF metadata + JavaScript + embedded files
  - DOCX hidden text (w:vanish) scan
  - MP3 ID3 tag anomaly scan
  - NTFS Alternate Data Streams (Windows)
  - Known tool signatures (StegHide, OpenStego, Camouflage, etc.)

If a password is provided, it also attempts to extract and decrypt the payload
across all applicable methods and reports the plaintext/binary.

Rich is used for pretty terminal output. All findings are also returned as a
dict so this can be called programmatically from other tools.

CSV export: call export_csv(reports, path) to write a list of scan reports.
"""

import csv
import io
import os
from pathlib import Path

from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich         import box

console = Console()


# ── File type routing ─────────────────────────────────────────────────────────

IMAGE_LOSSLESS  = {'.png', '.bmp', '.tiff', '.tif'}
IMAGE_RGBA      = {'.png', '.tiff', '.tif'}   # formats that support alpha
IMAGE_LOSSY     = {'.jpg', '.jpeg'}
IMAGE_ALL       = IMAGE_LOSSLESS | IMAGE_LOSSY
AUDIO_PCM       = {'.wav'}
AUDIO_MP3       = {'.mp3'}
DOCUMENT_PDF    = {'.pdf'}
DOCUMENT_DOCX   = {'.docx'}
ARCHIVE_ZIP     = {'.zip'}
TEXT_TYPES      = {'.txt', '.html', '.htm', '.xml', '.md', '.csv', '.js', '.py', '.json'}

from core.eof_append import EOF_MARKERS as EOF_SUPPORTED


def scan_file(
    file_path:  str,
    password:   str  = None,
    keyfile:    bytes = None,
    verbose:    bool = False,
) -> dict:
    """
    Comprehensive steganography scan of a single file.

    Returns a report dict with:
      file, size, type, findings, overall_suspicious, extracted_payload
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    suffix = path.suffix.lower()

    report = {
        'file':               str(file_path),
        'size':               os.path.getsize(file_path),
        'type':               suffix or '(no extension)',
        'findings':           [],
        'overall_suspicious': False,
        'extracted_payload':  None,
    }

    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
    except Exception as e:
        report['findings'].append({
            'method': 'File Read', 'confidence': 'error',
            'detail': str(e)
        })
        return report

    # ── 1. Image metadata anomalies ───────────────────────────────────────────
    if suffix in IMAGE_ALL:
        _check_image_metadata(file_path, suffix, raw_data, report)

    # ── 2. Statistical LSB analysis (lossless images only) ────────────────────
    if suffix in IMAGE_LOSSLESS:
        _check_lsb_statistics(file_path, report)

    # ── 3. RS analysis (lossless images) ─────────────────────────────────────
    if suffix in IMAGE_LOSSLESS:
        _check_rs_analysis(file_path, report)

    # ── 4. Alpha channel LSB analysis ─────────────────────────────────────────
    if suffix in IMAGE_RGBA:
        _check_alpha_lsb(file_path, report)

    # ── 5. EOF-append scan ────────────────────────────────────────────────────
    if suffix in EOF_SUPPORTED:
        _check_eof_append(file_path, report)

    # ── 6. Zero-width character scan ──────────────────────────────────────────
    if suffix in TEXT_TYPES:
        _check_zero_width(raw_data, report)

    # ── 7. ZIP comment scan ───────────────────────────────────────────────────
    if suffix in ARCHIVE_ZIP:
        _check_zip(file_path, report)

    # ── 8. PDF deep scan ──────────────────────────────────────────────────────
    if suffix in DOCUMENT_PDF:
        _check_pdf(file_path, report)

    # ── 9. DOCX hidden text scan ──────────────────────────────────────────────
    if suffix in DOCUMENT_DOCX:
        _check_docx(file_path, report)

    # ── 10. MP3 ID3 tag scan ──────────────────────────────────────────────────
    if suffix in AUDIO_MP3:
        _check_mp3(file_path, report)

    # ── 11. NTFS Alternate Data Streams (Windows only) ────────────────────────
    if os.name == 'nt':
        _check_ntfs_ads(file_path, report)

    # ── 12. Known tool signatures ─────────────────────────────────────────────
    _check_signatures(file_path, suffix, raw_data, report)

    # ── 13. Attempt extraction + decryption (if password given) ───────────────
    if password:
        _attempt_extraction(file_path, suffix, password, keyfile, report)

    return report


# ── Individual check functions ────────────────────────────────────────────────

def _check_image_metadata(file_path, suffix, raw_data, report):
    try:
        import piexif
        from PIL import Image

        img = Image.open(file_path)

        if 'exif' in img.info:
            try:
                exif = piexif.load(img.info['exif'])
            except Exception:
                exif = {}

            uc = exif.get('Exif', {}).get(0x9286, b'')
            if isinstance(uc, bytes):
                if b'NTv1:' in uc:
                    _add(report, 'EXIF UserComment', 'certain',
                         'NullTrace encrypted payload detected in UserComment')
                elif len(uc) > 20:
                    _add(report, 'EXIF UserComment', 'medium',
                         f'Unusual UserComment: {len(uc)} bytes '
                         f'("{uc[8:28].decode("utf-8", errors="replace")[:20]}...")')

            if exif.get('GPS'):
                _add(report, 'EXIF GPS', 'low',
                     f'GPS data present ({len(exif["GPS"])} GPS tags)')

            sw = exif.get('0th', {}).get(0x0131, b'')
            if isinstance(sw, bytes):
                sw = sw.decode('utf-8', errors='ignore').strip()
            if sw:
                _add(report, 'EXIF Software', 'info',
                     f'Software: "{sw}"', suspicious=False)

    except Exception:
        pass


def _check_lsb_statistics(file_path, report):
    from detector.statistical import analyze_image
    result = analyze_image(file_path)

    if result.get('error'):
        return

    chi  = result.get('chi_square', {})
    hist = result.get('lsb_histogram', {})

    if chi.get('suspicious'):
        _add(report, 'Statistical (Chi-Square)',
             chi.get('confidence', 'medium'), chi.get('detail', ''))

    if hist.get('suspicious'):
        _add(report, 'Statistical (LSB Distribution)',
             'medium', hist.get('detail', ''))


def _check_rs_analysis(file_path, report):
    """Run RS (Regular-Singular) analysis — strongest blind LSB detector."""
    try:
        from detector.rs_analysis import analyze_image
        result = analyze_image(file_path)
        if result.get('suspicious'):
            rate = result.get('embedding_rate', 0.0)
            conf = 'high' if rate > 0.20 else 'medium'
            _add(report, 'RS Analysis', conf, result.get('summary', ''))
        elif result.get('summary'):
            _add(report, 'RS Analysis', 'info',
                 result['summary'], suspicious=False)
    except Exception as e:
        _add(report, 'RS Analysis', 'info',
             f'RS analysis skipped: {e}', suspicious=False)


def _check_alpha_lsb(file_path, report):
    """Analyze alpha channel LSB distribution for RGBA images."""
    try:
        from core.alpha_lsb import scan as alpha_scan
        result = alpha_scan(file_path)
        for finding in result.get('findings', []):
            conf = 'medium' if result.get('detected') else 'info'
            susp = result.get('detected', False)
            _add(report, 'Alpha Channel LSB', conf, finding, suspicious=susp)
    except Exception:
        pass


def _check_eof_append(file_path, report):
    from core.eof_append import scan as eof_scan
    result = eof_scan(file_path)

    if result['detected']:
        detail = f"{result['extra_bytes']} bytes after EOF marker"
        if result.get('nulltrace_marker'):
            detail += ' — NullTrace NTEOF header present'
        _add(report, 'EOF Append', 'high', detail)


def _check_zero_width(raw_data, report):
    from core.zero_width import scan as zw_scan
    try:
        text   = raw_data.decode('utf-8', errors='ignore')
        result = zw_scan(text)
        if result['detected']:
            _add(report, 'Zero-Width Characters', 'high', result['detail'])
    except Exception:
        pass


def _check_zip(file_path, report):
    from core.zip_comment import scan as zip_scan
    result = zip_scan(file_path)
    for finding in result.get('findings', []):
        conf = 'high' if result.get('looks_binary') else 'medium'
        _add(report, 'ZIP Comment', conf, finding)


def _check_pdf(file_path, report):
    from core.pdf_meta import scan as pdf_scan
    result = pdf_scan(file_path)
    for finding in result.get('findings', []):
        conf = 'high' if result['detected'] else 'low'
        _add(report, 'PDF Metadata', conf, finding)


def _check_docx(file_path, report):
    """Scan DOCX for hidden (w:vanish) runs and NullTrace sentinel."""
    try:
        from core.docx_hidden import scan as docx_scan
        result = docx_scan(file_path)
        for finding in result.get('findings', []):
            conf = 'high' if result.get('detected') else 'low'
            susp = result.get('detected', False)
            _add(report, 'DOCX Hidden Text', conf, finding, suspicious=susp)
    except Exception as e:
        _add(report, 'DOCX Hidden Text', 'info',
             f'DOCX scan skipped: {e}', suspicious=False)


def _check_mp3(file_path, report):
    """Scan MP3 for ID3 anomalies and NullTrace comment markers."""
    try:
        from core.mp3_id3 import scan as mp3_scan
        result = mp3_scan(file_path)
        for finding in result.get('findings', []):
            conf = 'high' if result.get('detected') else 'low'
            susp = result.get('detected', False)
            _add(report, 'MP3 ID3 Tags', conf, finding, suspicious=susp)
    except Exception as e:
        _add(report, 'MP3 ID3 Tags', 'info',
             f'MP3 scan skipped: {e}', suspicious=False)


def _check_ntfs_ads(file_path, report):
    from core.ntfs_ads import scan as ads_scan
    result = ads_scan(file_path)
    for finding in result.get('findings', []):
        _add(report, 'NTFS ADS', 'high', finding)


def _check_signatures(file_path, suffix, raw_data, report):
    import piexif
    from detector.signatures import check_signatures

    exif_data = {}
    if suffix in ('.jpg', '.jpeg'):
        try:
            exif_data = piexif.load(file_path)
        except Exception:
            pass

    for sig in check_signatures(file_path, raw_data, exif_data):
        _add(report, f"Signature: {sig['tool']}", sig['confidence'], sig['detail'])


def _attempt_extraction(file_path, suffix, password, keyfile, report):
    """Try to extract and decrypt using all applicable methods."""
    from core import crypto

    candidates = []

    if suffix in IMAGE_LOSSLESS:
        from core.lsb import extract as lsb_x
        candidates.append(('LSB (image)', lambda: lsb_x(file_path, password)))

    if suffix in IMAGE_RGBA:
        from core.alpha_lsb import extract as alpha_x
        candidates.append(('Alpha LSB', lambda: alpha_x(file_path, password)))

    if suffix in IMAGE_LOSSLESS:
        from core.adaptive_lsb import extract as adp_x
        candidates.append(('Adaptive LSB', lambda: adp_x(file_path, password)))

    if suffix in IMAGE_LOSSY:
        from core.jpeg_exif import extract as exif_x
        candidates.append(('JPEG EXIF', lambda: exif_x(file_path)))
        try:
            from core.jpeg_dct import extract as dct_x
            candidates.append(('JPEG DCT', lambda: dct_x(file_path, password)))
        except ImportError:
            pass

    if suffix in AUDIO_PCM:
        from core.wav_lsb import extract as wav_x
        candidates.append(('WAV LSB', lambda: wav_x(file_path, password)))

    if suffix in AUDIO_MP3:
        try:
            from core.mp3_id3 import extract as mp3_x
            candidates.append(('MP3 ID3', lambda: mp3_x(file_path)))
        except ImportError:
            pass

    if suffix in DOCUMENT_DOCX:
        from core.docx_hidden import extract as docx_x
        candidates.append(('DOCX Hidden', lambda: docx_x(file_path)))

    if suffix in ARCHIVE_ZIP:
        from core.zip_comment import extract as zip_x
        candidates.append(('ZIP Comment', lambda: zip_x(file_path)))

    if suffix in DOCUMENT_PDF:
        from core.pdf_meta import extract as pdf_x
        candidates.append(('PDF Metadata', lambda: pdf_x(file_path)))

    if suffix in TEXT_TYPES:
        from core.zero_width import extract as zw_x
        candidates.append(('Zero-Width Chars',
                            lambda: _read_and_extract_zw(file_path, zw_x)))

    if suffix in EOF_SUPPORTED:
        from core.eof_append import extract as eof_x
        candidates.append(('EOF Append', lambda: eof_x(file_path)))

    for method_name, extractor in candidates:
        try:
            raw       = extractor()
            plaintext = crypto.decrypt(raw, password, keyfile)
            report['extracted_payload'] = {
                'method':    method_name,
                'raw_bytes': len(raw),
                'content':   plaintext,
            }
            _add(report, f'Extraction ({method_name})', 'certain',
                 f'Decrypted {len(plaintext)} bytes successfully')
            break
        except Exception:
            continue


def _read_and_extract_zw(file_path, extract_fn):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return extract_fn(f.read())


def _add(report: dict, method: str, confidence: str, detail: str,
         suspicious: bool = True):
    """Append a finding to the report."""
    report['findings'].append({
        'method':     method,
        'confidence': confidence,
        'detail':     detail,
    })
    if suspicious and confidence not in ('info', 'low'):
        report['overall_suspicious'] = True


# ── CSV export ────────────────────────────────────────────────────────────────

def export_csv(reports: list, output_path: str) -> None:
    """
    Write a list of scan report dicts to a CSV file.
    Each finding becomes its own row, correlated by file path.
    """
    fieldnames = ['file', 'size_bytes', 'type', 'overall_suspicious',
                  'method', 'confidence', 'detail', 'extracted_bytes']

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for rep in reports:
            ep_bytes = ''
            if rep.get('extracted_payload'):
                ep_bytes = rep['extracted_payload']['raw_bytes']

            if not rep['findings']:
                writer.writerow({
                    'file':               rep['file'],
                    'size_bytes':         rep['size'],
                    'type':               rep['type'],
                    'overall_suspicious': rep['overall_suspicious'],
                    'method':             '',
                    'confidence':         '',
                    'detail':             'No findings',
                    'extracted_bytes':    ep_bytes,
                })
            else:
                for finding in rep['findings']:
                    writer.writerow({
                        'file':               rep['file'],
                        'size_bytes':         rep['size'],
                        'type':               rep['type'],
                        'overall_suspicious': rep['overall_suspicious'],
                        'method':             finding['method'],
                        'confidence':         finding['confidence'],
                        'detail':             finding['detail'],
                        'extracted_bytes':    ep_bytes,
                    })


# ── Rich output ───────────────────────────────────────────────────────────────

CONF_COLORS = {
    'certain': 'bold red',
    'high':    'red',
    'medium':  'yellow',
    'low':     'dim yellow',
    'info':    'dim cyan',
    'error':   'red',
}


def print_report(report: dict):
    """Pretty-print a scan report to the terminal using Rich."""
    console.print()

    status_color = 'red'    if report['overall_suspicious'] else 'green'
    status_label = '[SUSPICIOUS]' if report['overall_suspicious'] else '[CLEAN]'
    size_kb      = report['size'] / 1024

    console.print(Panel(
        f"[bold]{report['file']}[/bold]\n"
        f"Size: {size_kb:.1f} KB  |  Type: {report['type']}  |  "
        f"[{status_color} bold]{status_label}[/{status_color} bold]",
        title="[bold cyan]NullTrace Scan Report[/bold cyan]",
        box=box.DOUBLE_EDGE,
        expand=False,
    ))

    if not report['findings']:
        console.print("[green]  No steganographic content detected.[/green]\n")
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta",
                  show_edge=False, pad_edge=False)
    table.add_column("Method",     style="cyan",  min_width=28)
    table.add_column("Confidence", min_width=10)
    table.add_column("Detail")

    for f in report['findings']:
        conf  = f.get('confidence', 'medium')
        color = CONF_COLORS.get(conf, 'white')
        table.add_row(
            f['method'],
            f"[{color}]{conf.upper()}[/{color}]",
            f['detail'],
        )

    console.print(table)

    ep = report.get('extracted_payload')
    if ep:
        content = ep['content']
        try:
            text = content.decode('utf-8')
            console.print(Panel(
                f"[green]{text}[/green]",
                title=f"[bold green]Extracted Payload — {ep['method']} "
                      f"({len(content)} bytes)[/bold green]",
                box=box.ROUNDED,
            ))
        except UnicodeDecodeError:
            hex_preview = content[:64].hex()
            if len(content) > 64:
                hex_preview += '...'
            console.print(Panel(
                f"[yellow]Binary payload ({len(content)} bytes)[/yellow]\n{hex_preview}",
                title=f"[bold yellow]Extracted Binary Payload — {ep['method']}[/bold yellow]",
                box=box.ROUNDED,
            ))

    console.print()
