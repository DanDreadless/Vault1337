"""
Pure-Python SimHash for malware sample similarity detection.

No external dependencies — uses only the standard library.

Algorithm
---------
1. Read up to MAX_INPUT_BYTES from the file.
2. Unpack all non-overlapping 4-byte grams via struct (single C call).
3. Hash each gram with FNV-1a 64-bit (fast, deterministic, no imports).
4. Maintain a 64-element integer accumulator.  For each bit position i,
   add +1 if bit i of the gram hash is set, -1 otherwise.
   To avoid an inner loop over 64 bits, each byte of the hash is looked up
   in a precomputed sign table (8 entries of ±1), giving 8 additions per byte.
5. Final fingerprint: set bit i if accumulator[i] > 0.
   Result is one 64-bit unsigned integer.

Similarity
----------
Hamming distance between two fingerprints — number of differing bits:

    bin(a ^ b).count('1')

    0       identical content
    1–7     very similar  (same family / variant, minor mutation)
    8–15    related       (shared code sections or resources)
    16+     probably unrelated

Performance
-----------
At stride=4 on a 5 MB file (~1.25 M grams), expect roughly 1–2 s on a
Raspberry Pi 5.  SimHash is computed once at upload time and stored, so
per-request similarity queries are O(n) table scans with no file I/O.
"""

import logging
import struct

logger = logging.getLogger(__name__)

MAX_INPUT_BYTES = 5 * 1024 * 1024   # 5 MB cap keeps upload latency acceptable
GRAM_SIZE       = 4                  # bytes per gram
GRAM_STRIDE     = 16                 # sample every 16 bytes; 4× faster than stride=4
BITS            = 64                 # with ~300K grams from a 5 MB file the
                                     # accumulator converges well for similarity

_FNV_PRIME  = 1099511628211          # FNV-1a 64-bit prime
_FNV_OFFSET = 14695981039346656037   # FNV-1a 64-bit offset basis
_MASK64     = 0xFFFFFFFFFFFFFFFF

# Precomputed table: _BYTE_SIGNS[byte_value] → tuple of 8 ints (±1),
# one per bit position 0-7.  Lets us update 8 accumulator slots per
# table lookup instead of looping over individual bits.
_BYTE_SIGNS: tuple = tuple(
    tuple(1 if (b >> i) & 1 else -1 for i in range(8))
    for b in range(256)
)


def simhash(data: bytes) -> int:
    """
    Compute a 64-bit SimHash fingerprint for raw bytes.

    Input is capped at MAX_INPUT_BYTES.  Returns 0 for empty / very short
    input (fewer than GRAM_SIZE bytes).
    """
    if len(data) > MAX_INPUT_BYTES:
        data = data[:MAX_INPUT_BYTES]
    if len(data) < GRAM_SIZE:
        return 0

    acc = [0] * BITS

    # Select grams at GRAM_STRIDE intervals.  Using struct.iter_unpack over
    # strided slices keeps gram extraction in C with minimal Python overhead.
    n_grams = (len(data) - GRAM_SIZE) // GRAM_STRIDE + 1
    grams = [
        struct.unpack_from('<I', data, i)[0]
        for i in range(0, len(data) - GRAM_SIZE + 1, GRAM_STRIDE)
    ]

    for gram_int in grams:
        # FNV-1a 64-bit over the 4 bytes of the gram (fully unrolled).
        h = _FNV_OFFSET
        h = ((h ^ (gram_int        & 0xFF)) * _FNV_PRIME) & _MASK64
        h = ((h ^ ((gram_int >> 8) & 0xFF)) * _FNV_PRIME) & _MASK64
        h = ((h ^ ((gram_int >>16) & 0xFF)) * _FNV_PRIME) & _MASK64
        h = ((h ^ ((gram_int >>24) & 0xFF)) * _FNV_PRIME) & _MASK64

        # Update 64 accumulators 8 bits at a time via the precomputed table.
        for byte_pos in range(8):
            signs = _BYTE_SIGNS[(h >> (byte_pos * 8)) & 0xFF]
            base  = byte_pos * 8
            acc[base    ] += signs[0]
            acc[base + 1] += signs[1]
            acc[base + 2] += signs[2]
            acc[base + 3] += signs[3]
            acc[base + 4] += signs[4]
            acc[base + 5] += signs[5]
            acc[base + 6] += signs[6]
            acc[base + 7] += signs[7]

    result = 0
    for i in range(BITS):
        if acc[i] > 0:
            result |= 1 << i
    return result


_SIGN_THRESHOLD = 1 << 63   # 2^63
_TWO_64         = 1 << 64   # 2^64


def _to_signed64(n: int) -> int:
    """Reinterpret an unsigned 64-bit integer as a signed 64-bit integer.

    Django's BigIntegerField (and SQLite/PostgreSQL) store 64-bit signed
    integers.  Values >= 2^63 would overflow, so we fold them into the
    negative half of the signed range.  The bit pattern is identical; only
    the Python int representation differs.
    """
    return n if n < _SIGN_THRESHOLD else n - _TWO_64


def _to_unsigned64(n: int) -> int:
    """Reverse _to_signed64 — convert a stored signed value back to unsigned."""
    return n if n >= 0 else n + _TWO_64


def simhash_file(file_path: str) -> tuple:
    """
    Read a file from disk and compute its SimHash fingerprint.

    Returns (fingerprint: int, bytes_hashed: int).
    fingerprint is stored as a signed 64-bit integer so it fits in
    Django's BigIntegerField on both SQLite (dev) and PostgreSQL (prod).
    bytes_hashed is stored alongside so the frontend can indicate when a
    large file was truncated before hashing.
    Returns (0, 0) on any read error.
    """
    try:
        with open(file_path, 'rb') as fh:
            data = fh.read(MAX_INPUT_BYTES)
        return _to_signed64(simhash(data)), len(data)
    except Exception as e:
        logger.warning("SimHash failed for %s: %s", file_path, e)
        return 0, 0


def hamming_distance(a: int, b: int) -> int:
    """Return the Hamming distance between two SimHash fingerprints.

    Accepts both signed (stored) and unsigned representations — converts
    to unsigned before XOR so bit patterns are compared correctly.
    """
    return bin(_to_unsigned64(a) ^ _to_unsigned64(b)).count('1')
