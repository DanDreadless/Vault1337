import os
import logging
import yara
from django.conf import settings

logger = logging.getLogger(__name__)

MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB
SCAN_TIMEOUT = 60  # seconds


def _format_matched_data(raw: bytes) -> str:
    """Return a readable representation of matched bytes."""
    try:
        text = raw.decode('utf-8')
        if text.isprintable():
            return repr(text)
    except (UnicodeDecodeError, ValueError):
        pass
    return raw.hex()


def run_yara(file_path):
    rules_path = settings.YARA_RULES_DIR

    file_size = os.path.getsize(file_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        return f"Error: File is too large to scan ({mb} MB). Maximum is 10 MB."

    # Collect all .yar files; test-compile each individually to skip broken ones.
    filepaths = {}
    compile_warnings = []
    for root, _dirs, files in os.walk(rules_path):
        for fname in sorted(files):
            if not fname.endswith('.yar'):
                continue
            rule_path = os.path.join(root, fname)
            namespace = os.path.splitext(fname)[0]
            try:
                yara.compile(filepath=rule_path)  # validate only
                filepaths[namespace] = rule_path
            except yara.SyntaxError as e:
                msg = f"Skipped {fname}: {e}"
                compile_warnings.append(msg)
                logger.error("YARA compile error — %s", msg)

    if not filepaths:
        return "Error: No valid YARA rule files found."

    try:
        rules = yara.compile(filepaths=filepaths)
    except Exception as e:
        logger.error("YARA bulk compile failed: %s", e)
        return f"Error: Failed to compile YARA rules: {e}"

    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except OSError as e:
        return f"Error: Could not read sample file: {e}"

    try:
        matches = rules.match(data=file_data, timeout=SCAN_TIMEOUT)
    except yara.TimeoutError:
        return "Error: YARA scan timed out (60 s limit)."
    except Exception as e:
        logger.error("YARA scan error: %s", e)
        return f"Error: YARA scan failed: {e}"

    if not matches and not compile_warnings:
        return "No YARA matches found."

    lines = []

    if compile_warnings:
        lines.append("=== Compile Warnings ===")
        for w in compile_warnings:
            lines.append(f"  [!] {w}")
        lines.append("")

    if not matches:
        lines.append("No YARA matches found.")
        return "\n".join(lines)

    lines.append(f"=== {len(matches)} Rule(s) Matched ===\n")

    for match in matches:
        tags = f"  Tags   : {', '.join(match.tags)}" if match.tags else ""
        meta_parts = []
        for k, v in (match.meta or {}).items():
            meta_parts.append(f"{k}={v}")
        meta = f"  Meta   : {', '.join(meta_parts)}" if meta_parts else ""

        lines.append(f"Rule     : {match.rule}  [{match.namespace}]")
        if tags:
            lines.append(tags)
        if meta:
            lines.append(meta)

        if match.strings:
            lines.append("  Strings:")
            # Group instances by identifier
            seen: dict[str, list] = {}
            for string_match in match.strings:
                ident = string_match.identifier
                for instance in string_match.instances:
                    seen.setdefault(ident, []).append(instance)

            for ident, instances in seen.items():
                # Show up to 3 instances per identifier to avoid flooding
                shown = instances[:3]
                for inst in shown:
                    offset_str = hex(inst.offset)
                    data_str = _format_matched_data(inst.matched_data)
                    lines.append(f"    {ident}  @ {offset_str}  →  {data_str}")
                if len(instances) > 3:
                    lines.append(f"    {ident}  … ({len(instances) - 3} more instances)")
        else:
            lines.append("  (matched on condition, no string patterns)")

        lines.append("")

    return "\n".join(lines)
