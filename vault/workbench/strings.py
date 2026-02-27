import os
import re
import logging

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
MIN_LEN = 4  # minimum printable string length


def get_strings(file_path, encoding):
    """
    Extract printable strings from a file.

    encoding: a Python codec name (utf-8, ascii, latin-1, utf-16, utf-32)
              or 'wide' for UTF-16LE wide-string extraction.
    """
    try:
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            mb = round(file_size / (1024 * 1024))
            return f"Error: File is too large to parse ({mb} MB, max 20 MB). Try the IOC extraction tool instead."

        with open(file_path, 'rb') as f:
            data = f.read()

        if encoding == 'wide':
            return _extract_wide(data)
        else:
            return _extract_encoded(data, encoding)

    except FileNotFoundError:
        return f"Error: File '{file_path}' not found."
    except PermissionError:
        return f"Error: Permission denied reading '{file_path}'."
    except Exception as e:
        logger.exception(e)
        return f"Error: {str(e)}"


def _extract_wide(data):
    """Extract UTF-16LE wide strings from raw bytes."""
    # Match MIN_LEN or more consecutive printable ASCII chars encoded as char+\x00
    pattern = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(MIN_LEN).encode() + rb',}')
    matches = pattern.findall(data)
    if not matches:
        return "No wide strings found."
    results = []
    for m in matches:
        try:
            results.append(m.decode('utf-16-le'))
        except Exception:
            pass
    return '\n'.join(results) if results else "No wide strings found."


def _extract_encoded(data, encoding):
    """Decode data with the given encoding and extract printable ASCII strings."""
    try:
        text = data.decode(encoding, errors='ignore')
    except LookupError:
        return f"Error: Unknown encoding '{encoding}'."
    matches = re.findall(r'[\x20-\x7E]{' + str(MIN_LEN) + r',}', text)
    if not matches:
        return f"No strings found (encoding: {encoding})."
    return '\n'.join(matches)
