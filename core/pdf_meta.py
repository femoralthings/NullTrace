"""
core/pdf_meta.py — PDF metadata steganography

PDFs have two metadata systems:
  1. DocInfo dictionary — classic key/value pairs (Title, Author, Creator...)
  2. XMP metadata — XML-based, more extensible

We use XMP with a custom namespace (nulltrace:) to store an encrypted hex payload.
This survives most PDF viewers and re-saves since XMP is passed through by default.

The scanner also checks for: JavaScript, embedded files, unusual stream objects,
and known tool signatures — all common hiding spots in hostile PDFs.
"""

import os
import pikepdf
from pikepdf import Dictionary, Name, String


NT_XMP_KEY = 'nulltrace:payload'


def hide(pdf_path: str, payload: bytes, output_path: str) -> None:
    """
    Embed payload as hex string in PDF XMP metadata under a custom key.
    """
    stat = os.stat(pdf_path)
    original_times = (stat.st_atime, stat.st_mtime)

    with pikepdf.open(pdf_path) as pdf:
        with pdf.open_metadata(set_pikepdf_as_editor=False) as meta:
            meta[NT_XMP_KEY] = payload.hex()
        pdf.save(output_path)

    os.utime(output_path, original_times)


def extract(pdf_path: str) -> bytes:
    """
    Extract payload from PDF XMP metadata.
    Returns raw (still-encrypted) bytes.
    """
    with pikepdf.open(pdf_path) as pdf:
        with pdf.open_metadata() as meta:
            hex_val = meta.get(NT_XMP_KEY)

    if not hex_val:
        raise ValueError("No NullTrace payload found in PDF metadata.")

    try:
        return bytes.fromhex(str(hex_val))
    except ValueError:
        raise ValueError("PDF metadata payload is malformed (not valid hex).")


def scan(pdf_path: str) -> dict:
    """
    Blind scan a PDF for all common hiding spots:
      - Custom/unusual XMP keys
      - DocInfo anomalies
      - Embedded files
      - JavaScript
      - Unusual stream counts vs page count
    """
    result = {'detected': False, 'findings': []}

    STANDARD_XMP_KEYS = {
        'dc:title', 'dc:creator', 'dc:description', 'dc:subject', 'dc:format',
        'xmp:CreateDate', 'xmp:ModifyDate', 'xmp:MetadataDate', 'xmp:CreatorTool',
        'pdf:Producer', 'pdf:Keywords', 'pdf:PDFVersion',
        'xmpMM:DocumentID', 'xmpMM:InstanceID',
    }

    try:
        with pikepdf.open(pdf_path) as pdf:

            # XMP metadata scan
            with pdf.open_metadata() as meta:
                if NT_XMP_KEY in meta:
                    result['detected'] = True
                    result['findings'].append(
                        f"NullTrace XMP key found: '{NT_XMP_KEY}'"
                    )
                for key in meta:
                    if key not in STANDARD_XMP_KEYS:
                        result['detected'] = True
                        result['findings'].append(f"Non-standard XMP key: '{key}'")

            # DocInfo anomalies
            try:
                docinfo = pdf.docinfo
                for key, value in docinfo.items():
                    key_str = str(key).lstrip('/')
                    standard = {
                        'Title', 'Author', 'Subject', 'Keywords', 'Creator',
                        'Producer', 'CreationDate', 'ModDate', 'Trapped'
                    }
                    if key_str not in standard:
                        result['detected'] = True
                        result['findings'].append(
                            f"Non-standard DocInfo key: '{key_str}' = '{str(value)[:80]}'"
                        )
            except Exception:
                pass

            # Embedded files
            try:
                names = pdf.Root.get('/Names')
                if names and '/EmbeddedFiles' in names:
                    result['detected'] = True
                    result['findings'].append("Embedded files found in PDF /Names tree")
            except Exception:
                pass

            # JavaScript
            try:
                if '/JavaScript' in pdf.Root or '/JS' in pdf.Root:
                    result['detected'] = True
                    result['findings'].append("JavaScript action found in PDF root")
                # Check all pages for JS
                for i, page in enumerate(pdf.pages):
                    annots = page.get('/Annots', [])
                    for annot in annots:
                        try:
                            if '/A' in annot and '/JS' in annot['/A']:
                                result['detected'] = True
                                result['findings'].append(
                                    f"JavaScript found in annotation on page {i + 1}"
                                )
                        except Exception:
                            pass
            except Exception:
                pass

            # Stream count vs page ratio (anomaly detection)
            try:
                n_pages   = len(pdf.pages)
                file_size = os.path.getsize(pdf_path)
                if n_pages > 0:
                    bpp = file_size // n_pages
                    if bpp > 500_000:
                        result['findings'].append(
                            f"Unusual size: {bpp:,} bytes/page "
                            f"({n_pages} pages, {file_size:,} bytes total)"
                        )
            except Exception:
                pass

    except Exception as e:
        result['findings'].append(f"Error opening PDF: {e}")

    return result
