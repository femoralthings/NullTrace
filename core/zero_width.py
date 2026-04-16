"""
core/zero_width.py — Zero-width character steganography

Zero-width characters are invisible Unicode codepoints that render as nothing
in browsers, word processors, terminals, and most text editors. They survive
copy-paste, email, Slack, Discord, and most document exports.

Real-world uses:
  - Document fingerprinting (watermarking a leak to trace who leaked it)
  - Hiding comms inside plaintext messages
  - Dead drops inside public web pages or social media posts
  - The DEADBEEF trick: embed known hex patterns to confirm receipt

Encoding scheme:
  ZWSP (U+200B) = bit 0
  ZWNJ (U+200C) = bit 1
  ZWJ  (U+200D) = byte separator (marks end of each 8-bit byte)

A payload byte of 0xDE (11011110) encodes as:
  1→ZWNJ 1→ZWNJ 0→ZWSP 1→ZWNJ 1→ZWNJ 1→ZWNJ 1→ZWNJ 0→ZWSP [ZWJ separator]
"""

ZW_ZERO = '\u200B'   # Zero Width Space          — encodes bit 0
ZW_ONE  = '\u200C'   # Zero Width Non-Joiner     — encodes bit 1
ZW_SEP  = '\u200D'   # Zero Width Joiner         — byte separator
ZW_ALL  = {ZW_ZERO, ZW_ONE, ZW_SEP}

# Also detect these less-common ZW chars used by other tools
ZW_EXTENDED = {
    '\u200B', '\u200C', '\u200D',   # Our encoding alphabet
    '\uFEFF',                        # BOM / Zero-width no-break space
    '\u2060',                        # Word joiner
    '\u180E',                        # Mongolian vowel separator
}


def hide(cover_text: str, payload: bytes, position: int = None) -> str:
    """
    Inject payload as invisible zero-width characters into cover_text.
    Default insertion point: after the first word (most natural position).

    Args:
        cover_text: The visible text that carries the hidden data
        payload:    Raw bytes to hide (should be pre-encrypted by caller)
        position:   Character index to insert at (None = after first word)

    Returns:
        Cover text with payload invisibly embedded
    """
    # Encode each byte as 8 ZW chars + 1 separator
    zw_chars = []
    for byte in payload:
        for i in range(7, -1, -1):
            zw_chars.append(ZW_ONE if (byte >> i) & 1 else ZW_ZERO)
        zw_chars.append(ZW_SEP)

    hidden_str = ''.join(zw_chars)

    # Find insertion position
    if position is None:
        space_idx = cover_text.find(' ')
        position = (space_idx + 1) if space_idx != -1 else len(cover_text)

    return cover_text[:position] + hidden_str + cover_text[position:]


def extract(text: str) -> bytes:
    """
    Extract payload from zero-width characters in text.
    Returns raw bytes (still encrypted — caller passes through crypto.decrypt).
    Raises ValueError if no ZW payload found or byte framing is invalid.
    """
    zw_sequence = [c for c in text if c in ZW_ALL]

    if not zw_sequence:
        raise ValueError("No zero-width characters found in text.")

    result       = bytearray()
    current_bits = []

    for char in zw_sequence:
        if char == ZW_SEP:
            if len(current_bits) == 8:
                result.append(int(''.join(str(b) for b in current_bits), 2))
            current_bits = []
        elif char == ZW_ONE:
            current_bits.append(1)
        elif char == ZW_ZERO:
            current_bits.append(0)

    if not result:
        raise ValueError("Zero-width characters present but no valid payload framing.")

    return bytes(result)


def fingerprint(cover_text: str, label: bytes) -> str:
    """
    Embed a unique identifier into cover_text for document fingerprinting.
    Each recipient gets the same visible text but a unique invisible watermark.
    Useful for leak tracing — recover the file, extract the label, know the source.

    Args:
        cover_text: The document text
        label:      Unique identifier (e.g. b'RECIPIENT_ID:007')
    """
    return hide(cover_text, label)


def scan(text: str) -> dict:
    """
    Blind scan: detect zero-width characters without knowing the password.
    Returns a report dict.
    """
    # Count each ZW character type
    counts = {char: text.count(char) for char in ZW_EXTENDED}
    found  = {char: n for char, n in counts.items() if n > 0}
    total  = sum(found.values())

    # Estimate payload size: 9 ZW chars per payload byte (8 bits + 1 separator)
    estimated_bytes = total // 9

    return {
        'detected':         bool(found),
        'total_zw_chars':   total,
        'breakdown':        {repr(k): v for k, v in found.items()},
        'estimated_bytes':  estimated_bytes,
        'detail':           (
            f"{total} zero-width chars found (~{estimated_bytes} hidden bytes)"
            if found else "No zero-width characters detected"
        )
    }
