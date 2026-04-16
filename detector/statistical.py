"""
detector/statistical.py — Statistical steganography detection

Two primary attacks against LSB steganography:

1. Chi-Square Attack
   In a natural image, pixel value pairs (2k, 2k+1) occur with similar frequency
   because neighboring intensity values are correlated by real-world light gradients.
   Sequential LSB embedding makes these pairs artificially equal — detectable by
   chi-square test. This attack fails against PRNG-spread embedding (NullTrace),
   but catches StegHide, naive LSB, and most open-source tools.

2. LSB Histogram Analysis
   Encrypted data is statistically uniform (that's what encryption does).
   If LSBs are 50% 0 and 50% 1, it looks like embedded encrypted data.
   Natural images have LSB distributions that reflect image content — typically
   NOT 50/50 unless the image has very uniform areas.

Note: Both tests have false-positive risk on highly compressed or synthetic images.
A single suspicious result is medium confidence; both suspicious = high confidence.
"""

from PIL import Image


def chi_square_attack(pixels: list, channel: int = 0) -> dict:
    """
    Chi-square attack against sequential LSB steganography.

    Theory:
      For a natural image, pairs of values (0,1), (2,3), (4,5)... each have
      some natural frequency. Sequential LSB embedding forces pair members
      to be equal — chi-square measures this deviation.

    A chi-square statistic near 0 means the pairs are suspiciously equal.
    A high chi-square means the distribution is natural.

    Args:
        pixels:  List of pixel tuples from img.getdata()
        channel: Which channel to analyze (0=R, 1=G, 2=B)

    Returns:
        Dict with statistic, suspicious flag, confidence, and detail string
    """
    # Extract specified channel
    channel_vals = [p[channel] if isinstance(p, (tuple, list)) else p for p in pixels]

    # Count occurrences of each 0-255 value
    counts = [0] * 256
    for v in channel_vals:
        counts[v] += 1

    chi_sq    = 0.0
    n_pairs   = 0
    total_obs = 0

    for k in range(128):  # pairs: (0,1), (2,3), ..., (254,255)
        v0 = counts[2 * k]
        v1 = counts[2 * k + 1]
        total = v0 + v1
        if total > 0:
            expected = total / 2.0
            chi_sq  += ((v0 - expected) ** 2) / expected
            chi_sq  += ((v1 - expected) ** 2) / expected
            n_pairs += 1
            total_obs += total

    # Normalize per pair to make comparable across image sizes
    normalized = chi_sq / n_pairs if n_pairs > 0 else 0.0

    # Decision: lower normalized chi-sq = more suspicious
    # Thresholds derived from empirical testing on natural images
    if normalized < 0.05:
        confidence = 'high'
        suspicious = True
    elif normalized < 0.20:
        confidence = 'medium'
        suspicious = True
    else:
        confidence = 'low'
        suspicious = False

    return {
        'chi_square':  round(normalized, 6),
        'suspicious':  suspicious,
        'confidence':  confidence,
        'detail':      (
            f"Chi-sq={normalized:.4f} on {'RGB'[channel]}-channel "
            f"({'suspicious — pairs too equal, possible sequential LSB' if suspicious else 'normal distribution'})"
        )
    }


def lsb_histogram_analysis(pixels: list) -> dict:
    """
    LSB distribution analysis across all three channels.

    Encrypted data = uniform random bytes = ~50% 0-bits and ~50% 1-bits.
    If a significant portion of the image's LSBs are near 50/50, it suggests
    a large uniform/random payload was embedded.

    A ratio in [0.48, 0.52] is suspicious.
    Natural images vary widely but rarely land exactly at 50%.
    """
    lsbs = []
    for p in pixels:
        if isinstance(p, (tuple, list)):
            for ch in p[:3]:   # R, G, B
                lsbs.append(int(ch) & 1)
        else:
            lsbs.append(int(p) & 1)

    if not lsbs:
        return {'detected': False, 'detail': 'No pixel data to analyze'}

    ones   = sum(lsbs)
    zeros  = len(lsbs) - ones
    ratio  = ones / len(lsbs)

    suspicious = 0.47 <= ratio <= 0.53

    return {
        'lsb_ratio':  round(ratio, 5),
        'lsb_ones':   ones,
        'lsb_zeros':  zeros,
        'suspicious': suspicious,
        'detail':     (
            f"LSB ratio {ratio:.4f} ({ratio*100:.1f}% ones) — "
            f"{'suspicious (near 50/50, consistent with embedded encrypted data)' if suspicious else 'normal'}"
        )
    }


def analyze_image(image_path: str) -> dict:
    """
    Run both statistical tests on an image. Returns consolidated report.
    """
    try:
        img    = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())

        chi_r = chi_square_attack(pixels, channel=0)  # Red
        chi_g = chi_square_attack(pixels, channel=1)  # Green
        chi_b = chi_square_attack(pixels, channel=2)  # Blue
        hist  = lsb_histogram_analysis(pixels)

        # Use the most suspicious channel for overall chi-square verdict
        most_suspicious_chi = min([chi_r, chi_g, chi_b], key=lambda x: x['chi_square'])
        overall_suspicious  = most_suspicious_chi['suspicious'] or hist['suspicious']

        return {
            'chi_square':        most_suspicious_chi,
            'lsb_histogram':     hist,
            'overall_suspicious': overall_suspicious,
            'image_size':        img.size,
            'pixel_count':       len(pixels),
        }

    except Exception as e:
        return {'error': str(e), 'overall_suspicious': False}
