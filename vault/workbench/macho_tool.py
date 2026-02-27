import logging
import math
from collections import Counter, defaultdict

import lief
from tabulate import tabulate

logger = logging.getLogger(__name__)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# Suspicious macOS framework / dylib imports mapped to category.
SUSPICIOUS_DYLIBS = {
    'Security':             'Keychain / Crypto',
    'CoreFoundation':       'Core Runtime',
    'SystemConfiguration':  'Network Config',
    'NetworkExtension':     'Network Extension / VPN',
    'EndpointSecurity':     'Endpoint Security Framework',
    'libssl':               'TLS / Crypto',
    'libcrypto':            'TLS / Crypto',
    'libc++':               'C++ Runtime',
    'AppKit':               'GUI / Screen Capture',
    'ScreenSaver':          'Screen Access',
    'IOKit':                'Hardware / Driver Access',
    'CoreGraphics':         'Screen Access',
    'AVFoundation':         'Camera / Microphone',
    'CoreLocation':         'Location Tracking',
    'AddressBook':          'Address Book Access',
    'Contacts':             'Contacts Access',
    'EventKit':             'Calendar / Reminder Access',
    'libSystem':            'System Library',
    'dyld':                 'Dynamic Loader',
}


def macho_subtool(sub_tool, file_path):
    """Dispatch to a Mach-O sub-tool. Returns a formatted string."""
    try:
        fat = lief.MachO.parse(file_path)
        if fat is None:
            return "Error: Could not parse Mach-O binary (invalid format or unsupported type)."
        binary = fat[0]
    except Exception as e:
        logger.exception(e)
        return f"Error parsing Mach-O: {str(e)}"

    try:
        if sub_tool == 'header':
            return _header(binary, fat)
        elif sub_tool == 'load_commands':
            return _load_commands(binary)
        elif sub_tool == 'dylibs':
            return _dylibs(binary)
        elif sub_tool == 'exports':
            return _exports(binary)
        elif sub_tool == 'symbols':
            return _symbols(binary)
        elif sub_tool == 'sections':
            return _sections(binary)
        elif sub_tool == 'codesig':
            return _codesig(binary)
        else:
            return f"Unknown sub-tool: {sub_tool}"
    except Exception as e:
        logger.exception(e)
        return f"Error running Mach-O sub-tool '{sub_tool}': {str(e)}"


def _header(binary, fat):
    h = binary.header
    is_fat = len(fat) > 1
    lines = [
        f"Magic:              {h.magic}",
        f"CPU Type:           {h.cpu_type}",
        f"CPU Subtype:        {h.cpu_subtype}",
        f"File Type:          {h.file_type}",
        f"Load Commands:      {h.nb_cmds}",
        f"Load Commands Size: {h.sizeof_cmds} bytes",
        f"Flags:              0x{int(h.flags):08x}",
        f"Fat Binary:         {'Yes (' + str(len(fat)) + ' architectures)' if is_fat else 'No'}",
    ]
    if is_fat:
        lines.append("")
        lines.append("Architectures:")
        for i, arch in enumerate(fat):
            lines.append(f"  [{i}] {arch.header.cpu_type} / {arch.header.cpu_subtype}")
    return '\n'.join(lines)


def _load_commands(binary):
    result = []
    headers = ["#", "Command", "Size", "Details"]
    for i, cmd in enumerate(binary.commands):
        cmd_str = str(cmd.command)
        size = cmd.size
        details = ""
        # Extract useful details for common load commands
        try:
            if hasattr(cmd, 'name'):
                details = cmd.name
        except Exception:
            pass
        result.append([i, cmd_str, size, details])
    if not result:
        return "No load commands found."
    return tabulate(result, headers=headers, tablefmt="grid")


def _dylibs(binary):
    try:
        libs = binary.libraries
    except Exception:
        libs = []

    if not libs:
        return "No dynamic library imports found."

    result = []
    headers = ["Library", "Compatibility Version", "Current Version", "Category"]
    for lib in libs:
        name = lib.name if lib.name else "(unnamed)"
        # Strip path to get base name for category lookup
        base = name.split('/')[-1].split('.')[0]
        category = SUSPICIOUS_DYLIBS.get(base, '')
        compat = str(lib.compatibility_version) if hasattr(lib, 'compatibility_version') else ""
        current = str(lib.current_version) if hasattr(lib, 'current_version') else ""
        result.append([name, compat, current, category])

    return tabulate(result, headers=headers, tablefmt="grid")


def _exports(binary):
    try:
        exported = list(binary.exported_functions)
    except Exception:
        exported = []

    if not exported:
        return "No exported functions found."

    result = []
    headers = ["Name", "Address"]
    for func in exported:
        name = func.name if func.name else "(unnamed)"
        addr = hex(func.address) if func.address else "N/A"
        result.append([name, addr])

    return f"Total exports: {len(result)}\n\n" + tabulate(result, headers=headers, tablefmt="grid")


def _symbols(binary):
    try:
        syms = [s for s in binary.symbols if s.name]
    except Exception:
        syms = []

    if not syms:
        return "No symbols found."

    result = []
    headers = ["Name", "Type", "Value"]
    for sym in syms[:500]:  # cap at 500 to avoid excessive output
        result.append([sym.name, str(sym.type), hex(sym.value) if sym.value else "0x0"])

    suffix = f"\n(showing first 500 of {len(syms)})" if len(syms) > 500 else ""
    return tabulate(result, headers=headers, tablefmt="grid") + suffix


def _sections(binary):
    result = []
    headers = ["Segment", "Section", "Size", "Offset", "VA", "Entropy"]
    for section in binary.sections:
        data = bytes(section.content)
        ent = _entropy(data) if data else 0.0
        flag = " [!] HIGH" if ent > 7.0 else (" [~] elevated" if ent > 6.5 else "")
        seg = section.segment_name if hasattr(section, 'segment_name') else ""
        result.append([
            seg,
            section.name,
            section.size,
            hex(section.offset),
            hex(section.virtual_address),
            f"{ent:.4f}{flag}",
        ])
    if not result:
        return "No sections found."
    return tabulate(result, headers=headers, tablefmt="grid")


def _codesig(binary):
    lines = []
    try:
        sig = binary.code_signature
        if sig is None:
            return "No code signature found."
        lines.append(f"Code Signature Present: Yes")
        lines.append(f"Data Size:              {sig.data_size} bytes")
        lines.append(f"Offset:                 0x{sig.data_offset:08x}")
    except Exception:
        return "No code signature found (or error reading signature data)."

    # Check for entitlements
    try:
        ent = binary.code_signature_data
        if ent:
            lines.append(f"\nRaw signature data (first 256 bytes hex):\n{bytes(ent[:256]).hex()}")
    except Exception:
        pass

    return '\n'.join(lines)
