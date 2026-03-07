"""
Decode tool — single-layer deobfuscation primitives.

Sub-tools
---------
base64          Standard Base64 decode (RFC 4648).  Tries UTF-8 then
                falls back to a hex dump for binary output.
base64_url      URL-safe Base64 (- and _ instead of + and /).
hex             Decode a hex string (strips whitespace / 0x prefixes).
rot13           ROT13 character substitution (ASCII letters only).
xor_brute       1-byte XOR key brute-force: tries all 256 keys, scores
                each plaintext by printable-ASCII ratio, returns the top
                candidates so the analyst can judge.

These cover the most common single-layer obfuscation seen in commodity
malware (PowerShell stagers, VBScript droppers, macro payloads, etc.).
Multi-layer or custom encodings require chaining tools manually.
"""

import base64
import logging
import string

logger = logging.getLogger(__name__)

_MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MB; blobs larger than this are unusual
_PRINTABLE = set(string.printable)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bytes_to_text(data: bytes, label: str) -> str:
    """Try to render bytes as UTF-8 text; fall back to annotated hex dump."""
    try:
        text = data.decode('utf-8')
        return f"[{label}] decoded {len(data)} byte(s) as UTF-8:\n\n{text}"
    except UnicodeDecodeError:
        pass
    # Binary output — show hex dump (16 bytes per line)
    lines = [f"[{label}] decoded {len(data)} byte(s) — binary output (hex dump):"]
    for i in range(0, min(len(data), 512), 16):
        chunk = data[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {i:08x}  {hex_part:<47}  {asc_part}")
    if len(data) > 512:
        lines.append(f"  ... ({len(data) - 512} more bytes truncated)")
    return '\n'.join(lines)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if chr(b) in _PRINTABLE) / len(data)


# ---------------------------------------------------------------------------
# Sub-tool implementations
# ---------------------------------------------------------------------------

def _decode_base64(data: bytes, urlsafe: bool = False) -> str:
    # Strip whitespace that editors / network protocols commonly insert.
    stripped = data.replace(b'\r', b'').replace(b'\n', b'').replace(b' ', b'')
    # Add padding if missing.
    padding = (-len(stripped)) % 4
    padded = stripped + b'=' * padding
    try:
        if urlsafe:
            decoded = base64.urlsafe_b64decode(padded)
        else:
            decoded = base64.b64decode(padded)
    except Exception as e:
        return f"[!] Base64 decode failed: {e}"
    label = 'base64url' if urlsafe else 'base64'
    return _bytes_to_text(decoded, label)


def _decode_hex(data: bytes) -> str:
    text = data.decode('latin-1').strip()
    # Remove common prefixes / separators (0x, \x, spaces, colons)
    text = text.replace('0x', '').replace('\\x', '').replace(':', '').replace(' ', '').replace('\n', '')
    if not text:
        return "[!] Input is empty after stripping hex separators."
    if len(text) % 2 != 0:
        return f"[!] Hex string has odd length ({len(text)} chars) — possibly truncated or malformed."
    try:
        decoded = bytes.fromhex(text)
    except ValueError as e:
        return f"[!] Hex decode failed: {e}"
    return _bytes_to_text(decoded, 'hex')


def _decode_rot13(data: bytes) -> str:
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        text = data.decode('latin-1', errors='replace')
    result = text.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm',
    ))
    return f"[rot13] {len(data)} byte(s) decoded:\n\n{result}"


def _xor_brute(data: bytes) -> str:
    if len(data) > _MAX_INPUT_BYTES:
        data = data[:_MAX_INPUT_BYTES]

    results = []
    for key in range(256):
        plain = bytes(b ^ key for b in data)
        score = _printable_ratio(plain)
        results.append((score, key, plain))

    # Sort by score descending; show top 5 candidates with score > 0.7
    results.sort(key=lambda x: x[0], reverse=True)
    top = [r for r in results if r[0] > 0.70][:5]

    if not top:
        # Relax threshold — show best 3 regardless
        top = results[:3]

    lines = [
        f"XOR brute-force over {len(data)} byte(s) — top candidate(s):",
        "",
    ]
    for score, key, plain in top:
        preview_raw = plain[:200]
        try:
            preview = preview_raw.decode('utf-8', errors='replace')
        except Exception:
            preview = preview_raw.decode('latin-1', errors='replace')
        lines.append(f"Key: 0x{key:02x} ({key})  —  printable ratio: {score:.1%}")
        lines.append(f"Preview: {preview!r}")
        lines.append("")

    lines.append(
        "Tip: if a candidate looks correct, use the hex viewer or strings tool\n"
        "on the XOR-decoded content for further analysis."
    )
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_SUB_TOOLS = {'base64', 'base64_url', 'hex', 'rot13', 'xor_brute'}


def decode(file_path: str, sub_tool: str) -> str:
    """
    Read file_path and apply the requested decode operation.
    Returns a formatted string result suitable for display in the frontend.
    """
    if sub_tool not in _SUB_TOOLS:
        supported = ', '.join(sorted(_SUB_TOOLS))
        return f"Unknown decode sub-tool '{sub_tool}'. Supported: {supported}"

    try:
        with open(file_path, 'rb') as fh:
            data = fh.read(_MAX_INPUT_BYTES)
    except Exception as e:
        return f"Error reading file: {e}"

    if not data:
        return "File is empty."

    if sub_tool == 'base64':
        return _decode_base64(data, urlsafe=False)
    if sub_tool == 'base64_url':
        return _decode_base64(data, urlsafe=True)
    if sub_tool == 'hex':
        return _decode_hex(data)
    if sub_tool == 'rot13':
        return _decode_rot13(data)
    if sub_tool == 'xor_brute':
        return _xor_brute(data)
