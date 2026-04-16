"""
detector/rs_analysis.py — Regular-Singular (RS) steganography detection

RS analysis is the strongest known blind LSB detector. Unlike chi-square,
which only looks at LSB frequency, RS exploits spatial correlations between
adjacent pixels — making it effective even against PRNG-spread embedding.

Algorithm (Fridrich et al. 2001):
  1. Divide the channel into groups of n adjacent pixels.
  2. Apply a flipping mask F = [0,1,0,1,...] to each group.
  3. Measure smoothness f(x) = sum of |x[i+1] - x[i]| within the group.
  4. Classify each group:
       Regular (R):  f(flip(x)) > f(x)  — flipping increased roughness
       Singular (S): f(flip(x)) < f(x)  — flipping decreased roughness
       Unusable (U): f(flip(x)) == f(x)
  5. Do the same with a negative mask F' (bit flip of F).
  6. In a clean image: R > S and R' > S' (asymmetric).
     After LSB embedding:  R -> S, R' -> S' (they converge).
  7. Solve for embedding rate p using the RS equations.

Embedding rate interpretation:
  p = 0.0      → clean image (no detectable LSB embedding)
  p = 0.0-0.1  → borderline / uncertain
  p = 0.1-0.5  → significant embedding likely
  p > 0.5      → heavy embedding (>50% of LSBs modified)
"""

import numpy as np
from PIL import Image


GROUP_SIZE = 4  # pixels per RS group


def _smoothness(group: np.ndarray) -> float:
    """Sum of absolute differences between adjacent elements."""
    return float(np.sum(np.abs(np.diff(group.astype(int)))))


def _apply_mask(group: np.ndarray, mask: np.ndarray, negative: bool) -> np.ndarray:
    """
    Apply flipping mask to a pixel group.
    Positive mask: flip LSB (XOR with 1) where mask=1.
    Negative mask: invert-flip (XOR between 0 and 1 reversed) where mask=1.
      Specifically: 0->255, 255->0 ... simplified to LSB inversion on -1 values:
      negative mask maps x -> x^1 if mask=1 THEN maps 0->-1, 1->0 (shift left).
      Standard implementation: negative flip does (x+1) if x%2==0, (x-1) if x%2==1.
    """
    result = group.copy().astype(int)
    for i, m in enumerate(mask):
        if m == 1:
            if not negative:
                result[i] ^= 1           # flip LSB
            else:
                # Negative flip: 0->-1, even->odd-1, odd->even+1
                if result[i] % 2 == 0:
                    result[i] -= 1
                else:
                    result[i] += 1
    return result


def _rs_counts(pixels: np.ndarray, mask: np.ndarray) -> tuple:
    """
    Count Regular, Singular, Unusable groups for a given mask.
    Returns (R, S, U) as fractions of total groups.
    """
    n = len(pixels)
    n_groups = n // GROUP_SIZE
    if n_groups == 0:
        return 0.0, 0.0, 0.0

    R_pos, S_pos, U_pos = 0, 0, 0
    R_neg, S_neg, U_neg = 0, 0, 0

    for g in range(n_groups):
        group = pixels[g * GROUP_SIZE : (g + 1) * GROUP_SIZE]

        f_orig  = _smoothness(group)
        flipped_pos = _apply_mask(group, mask, negative=False)
        flipped_neg = _apply_mask(group, mask, negative=True)

        f_pos = _smoothness(np.clip(flipped_pos, 0, 255))
        f_neg = _smoothness(np.clip(flipped_neg, 0, 255))

        # Positive mask classification
        if f_pos > f_orig:
            R_pos += 1
        elif f_pos < f_orig:
            S_pos += 1
        else:
            U_pos += 1

        # Negative mask classification
        if f_neg > f_orig:
            R_neg += 1
        elif f_neg < f_orig:
            S_neg += 1
        else:
            U_neg += 1

    total = float(n_groups)
    return (
        R_pos / total, S_pos / total, U_pos / total,
        R_neg / total, S_neg / total, U_neg / total,
    )


def _estimate_embedding_rate(R: float, S: float,
                              R_neg: float, S_neg: float) -> float:
    """
    Estimate LSB embedding rate p from RS statistics.
    Uses the quadratic RS formula derived in Fridrich et al. 2001.
    Returns p in [0, 1] or -1.0 if the equation has no real solution.
    """
    # d = R - S, d' = R' - S'
    d      = R - S
    d_neg  = R_neg - S_neg

    # Solve: 2(d' - d) * p^2 + (d - d') * p + (d - d_neg) = 0
    a = 2.0 * (d_neg - d)
    b = d - d_neg
    # Simpler approximate form for small embedding rates:
    # p ≈ (R_neg - S_neg - R + S) / (R_neg - S_neg + R - S)
    # We use the discriminant form for accuracy.
    if abs(a) < 1e-10:
        # Linear case
        if abs(b) < 1e-10:
            return 0.0
        p = (S - d) / b
    else:
        discriminant = b * b - 4 * a * (d - d_neg)
        if discriminant < 0:
            return 0.0  # no real solution → effectively 0
        sqrt_disc = discriminant ** 0.5
        p1 = (-b + sqrt_disc) / (2 * a)
        p2 = (-b - sqrt_disc) / (2 * a)
        # Choose the root closest to [0, 1]
        candidates = [p for p in (p1, p2) if 0.0 <= p <= 1.0]
        if not candidates:
            return 0.0
        p = min(candidates)  # prefer lower (more conservative)

    return max(0.0, min(1.0, p))


MASK = np.array([0, 1, 0, 1], dtype=int)  # standard RS mask for group size 4


def analyze_channel(channel_pixels: np.ndarray) -> dict:
    """
    Run RS analysis on a single channel (1D array of uint8 values).
    Returns a dict with R, S, R', S', embedding_rate, and verdict.
    """
    flat = channel_pixels.flatten()
    counts = _rs_counts(flat, MASK)
    R, S, _U, R_neg, S_neg, _U_neg = counts

    p = _estimate_embedding_rate(R, S, R_neg, S_neg)

    return {
        'R':              round(R,     4),
        'S':              round(S,     4),
        'R_neg':          round(R_neg, 4),
        'S_neg':          round(S_neg, 4),
        'embedding_rate': round(p,     4),
        'suspicious':     p > 0.05,
    }


def analyze_image(image_path: str) -> dict:
    """
    Run RS analysis on all three RGB channels of an image.
    Returns per-channel results and an overall verdict.
    """
    result = {
        'method':   'RS Analysis',
        'channels': {},
        'suspicious': False,
        'embedding_rate': 0.0,
        'summary': '',
    }

    try:
        img    = Image.open(image_path).convert('RGB')
        arr    = np.array(img)
        names  = ('R', 'G', 'B')

        rates = []
        for i, name in enumerate(names):
            ch_result = analyze_channel(arr[:, :, i])
            result['channels'][name] = ch_result
            rates.append(ch_result['embedding_rate'])

        avg_rate = sum(rates) / len(rates)
        result['embedding_rate'] = round(avg_rate, 4)
        result['suspicious']     = avg_rate > 0.05

        if avg_rate < 0.02:
            result['summary'] = f"Clean (avg embedding rate {avg_rate:.3f})"
        elif avg_rate < 0.10:
            result['summary'] = f"Borderline — possible light embedding ({avg_rate:.3f})"
        elif avg_rate < 0.40:
            result['summary'] = f"SUSPICIOUS — significant LSB embedding detected ({avg_rate:.3f})"
        else:
            result['summary'] = f"HEAVY EMBEDDING — rate {avg_rate:.3f} (>{int(avg_rate*100)}% LSBs modified)"

    except Exception as e:
        result['summary'] = f"RS analysis failed: {e}"

    return result
