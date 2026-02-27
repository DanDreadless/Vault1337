import hashlib
import logging
import math
from collections import Counter, defaultdict

import pefile

logger = logging.getLogger(__name__)


# Maps API name → category for suspicious import reporting.
# Covers process injection, anti-debug/anti-VM, dynamic loading,
# execution, and network download primitives.
SUSPICIOUS_APIS = {
    # ── Process Injection ─────────────────────────────────────────────────
    'VirtualAlloc':             'Process Injection',
    'VirtualAllocEx':           'Process Injection',
    'VirtualProtect':           'Process Injection',
    'VirtualProtectEx':         'Process Injection',
    'WriteProcessMemory':       'Process Injection',
    'ReadProcessMemory':        'Process Injection',
    'CreateRemoteThread':       'Process Injection',
    'CreateRemoteThreadEx':     'Process Injection',
    'QueueUserAPC':             'Process Injection',
    'SetThreadContext':         'Process Injection',
    'GetThreadContext':         'Process Injection',
    'SuspendThread':            'Process Injection',
    'ResumeThread':             'Process Injection',
    'NtUnmapViewOfSection':     'Process Injection',
    'ZwUnmapViewOfSection':     'Process Injection',
    'NtCreateSection':          'Process Injection',
    'MapViewOfFile':            'Process Injection',
    # ── Anti-Debug / Anti-VM ──────────────────────────────────────────────
    'IsDebuggerPresent':            'Anti-Debug',
    'CheckRemoteDebuggerPresent':   'Anti-Debug',
    'NtQueryInformationProcess':    'Anti-Debug',
    'ZwQueryInformationProcess':    'Anti-Debug',
    'NtSetInformationThread':       'Anti-Debug',
    'OutputDebugStringA':           'Anti-Debug',
    'OutputDebugStringW':           'Anti-Debug',
    'BlockInput':                   'Anti-Debug',
    'SetUnhandledExceptionFilter':  'Anti-Debug',
    'FindWindowA':                  'Anti-Debug',
    'FindWindowW':                  'Anti-Debug',
    'GetTickCount':                 'Anti-Debug / Timing',
    'GetTickCount64':               'Anti-Debug / Timing',
    'QueryPerformanceCounter':      'Anti-Debug / Timing',
    # ── Dynamic Loading ───────────────────────────────────────────────────
    'LoadLibraryA':             'Dynamic Loading',
    'LoadLibraryW':             'Dynamic Loading',
    'LoadLibraryExA':           'Dynamic Loading',
    'LoadLibraryExW':           'Dynamic Loading',
    'GetProcAddress':           'Dynamic Loading',
    'LdrLoadDll':               'Dynamic Loading',
    'RtlDecompressBuffer':      'Decompression',
    # ── Execution ─────────────────────────────────────────────────────────
    'WinExec':                  'Execution',
    'ShellExecuteA':            'Execution',
    'ShellExecuteW':            'Execution',
    'CreateProcessA':           'Execution',
    'CreateProcessW':           'Execution',
    # ── Process Access ────────────────────────────────────────────────────
    'OpenProcess':              'Process Access',
    'OpenThread':               'Process Access',
    # ── Network / Download ────────────────────────────────────────────────
    'URLDownloadToFileA':       'Download',
    'URLDownloadToFileW':       'Download',
    'InternetOpenUrlA':         'Network',
    'InternetOpenUrlW':         'Network',
    'HttpOpenRequestA':         'Network',
    'HttpOpenRequestW':         'Network',
}

# Known packer / protector section names mapped to tool name.
PACKER_SECTIONS = {
    'UPX0':     'UPX',      'UPX1':     'UPX',      'UPX2':     'UPX',
    '.upx':     'UPX',
    'MPRESS1':  'MPRESS',   'MPRESS2':  'MPRESS',
    '.MPRESS1': 'MPRESS',   '.MPRESS2': 'MPRESS',
    '.petite':  'Petite',
    '.nsp0':    'NsPack',   '.nsp1':    'NsPack',    '.nsp2':    'NsPack',
    'PEC2':     'PECompact','PEC2MO':   'PECompact',
    '.aspack':  'ASPack',   '.adata':   'ASPack',    'ASPack':   'ASPack',
    '.vmp0':    'VMProtect','.vmp1':    'VMProtect', '.vmp2':    'VMProtect',
    '.themida': 'Themida',
    '.enigma1': 'Enigma Protector', '.enigma2': 'Enigma Protector',
    '.shrink1': 'FSG',      '.shrink2': 'FSG',
    'pebundle': 'PEBundle',
    '.WISE':    'WISE Installer',
    '.packed':  'Generic Packer',
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def pefile_subtool(sub_tool, file_path):
    """Dispatch to a pefile sub-tool. Returns a formatted string."""
    try:
        pe = pefile.PE(file_path, fast_load=False)
    except pefile.PEFormatError as e:
        return f"PE format error: {str(e)}"
    except Exception as e:
        logger.exception(e)
        return f"Error loading PE: {str(e)}"

    try:
        if sub_tool == 'imphash':
            return _imphash(pe)
        elif sub_tool == 'rich_hash':
            return _rich_hash(pe)
        elif sub_tool == 'resources':
            return _resources(pe)
        elif sub_tool == 'version_info':
            return _version_info(pe)
        elif sub_tool == 'overlay':
            return _overlay(pe)
        elif sub_tool == 'suspicious_imports':
            return _suspicious_imports(pe)
        elif sub_tool == 'section_entropy':
            return _section_entropy(pe)
        elif sub_tool == 'packer':
            return _packer(pe)
        else:
            return f"Unknown sub-tool: {sub_tool}"
    except Exception as e:
        logger.exception(e)
        return f"Error running pefile sub-tool '{sub_tool}': {str(e)}"
    finally:
        pe.close()  # release file handle so _temp_copy can delete the temp file on Windows


def _imphash(pe):
    try:
        h = pe.get_imphash()
        return f"Import Hash (imphash): {h}" if h else "No import hash available (no imports or empty)."
    except Exception as e:
        return f"Error computing imphash: {str(e)}"


def _rich_hash(pe):
    try:
        if not hasattr(pe, 'RICH_HEADER') or pe.RICH_HEADER is None:
            return "No Rich Header found."
        # pefile stores rich header entries in .values (list of [prodId, count] pairs)
        entries = pe.RICH_HEADER.values
        if not entries:
            return "Rich Header present but no entries."
        data = b''
        for entry in entries:
            if isinstance(entry, (list, tuple)):
                id_val, count_val = int(entry[0]), int(entry[1])
            else:
                id_val = int(getattr(entry, 'id', 0))
                count_val = int(getattr(entry, 'count', 0))
            data += id_val.to_bytes(4, 'little') + count_val.to_bytes(4, 'little')
        h = hashlib.md5(data).hexdigest()
        return f"Rich Header Hash (MD5): {h}"
    except Exception as e:
        return f"Error computing rich hash: {str(e)}"


def _resources(pe):
    try:
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return "No resources found."
        lines = [f"{'Type':<20} {'Name':<20} {'Lang':<8} {'Size':>10} {'Offset':>10}"]
        lines.append('-' * 72)
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = str(res_type.name) if res_type.name else str(res_type.struct.Id)
            for res_id in res_type.directory.entries:
                id_name = str(res_id.name) if res_id.name else str(res_id.struct.Id)
                for res_lang in res_id.directory.entries:
                    lang = res_lang.data.lang
                    size = res_lang.data.struct.Size
                    offset = res_lang.data.struct.OffsetToData
                    lines.append(f"{type_name:<20} {id_name:<20} {lang:<8} {size:>10} {offset:>10}")
        return '\n'.join(lines)
    except Exception as e:
        return f"Error listing resources: {str(e)}"


def _version_info(pe):
    try:
        if not hasattr(pe, 'FileInfo') or not pe.FileInfo:
            return "No version information found."
        lines = []
        for file_info_list in pe.FileInfo:
            for info in file_info_list:
                if hasattr(info, 'StringTable'):
                    for st in info.StringTable:
                        for k, v in st.entries.items():
                            k_str = k.decode('utf-8', errors='replace') if isinstance(k, bytes) else str(k)
                            v_str = v.decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v)
                            lines.append(f"{k_str:<30} {v_str}")
        return '\n'.join(lines) if lines else "No string version info found."
    except Exception as e:
        return f"Error getting version info: {str(e)}"


def _overlay(pe):
    try:
        overlay = pe.get_overlay()
        if overlay is None or len(overlay) == 0:
            return "No overlay detected."
        preview = overlay[:64].hex()
        return f"Overlay size: {len(overlay)} bytes\nFirst 64 bytes (hex): {preview}"
    except Exception as e:
        return f"Error checking overlay: {str(e)}"


def _suspicious_imports(pe):
    try:
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return "No imports found."
        found = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            lib = entry.dll.decode('utf-8', errors='replace') if isinstance(entry.dll, bytes) else str(entry.dll)
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode('utf-8', errors='replace') if isinstance(imp.name, bytes) else str(imp.name)
                    if name in SUSPICIOUS_APIS:
                        found.append((SUSPICIOUS_APIS[name], lib, name))
        if not found:
            return "No suspicious imports detected."
        by_cat = defaultdict(list)
        for category, lib, name in found:
            by_cat[category].append(f"  {lib} -> {name}")
        lines = [f"Suspicious imports found ({len(found)} total):\n"]
        for cat in sorted(by_cat):
            lines.append(f"[{cat}]")
            lines.extend(by_cat[cat])
            lines.append("")
        return '\n'.join(lines)
    except Exception as e:
        return f"Error checking suspicious imports: {str(e)}"


def _section_entropy(pe):
    try:
        lines = [f"{'Section':<12} {'Entropy':>10}  Status"]
        lines.append('-' * 40)
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            entropy = section.get_entropy()
            flag = ' [!] HIGH' if entropy > 7.0 else ''
            lines.append(f"{name:<12} {entropy:>10.4f}{flag}")
        return '\n'.join(lines)
    except Exception as e:
        return f"Error computing section entropy: {str(e)}"


def _packer(pe):
    """Detect packer/protector indicators via section names, EP entropy, and section entropy profile."""
    findings = []

    # 1. Known packer section names
    hits = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
        if name in PACKER_SECTIONS:
            hits.append(f"  '{name}' → {PACKER_SECTIONS[name]}")
    if hits:
        findings.append("[!] Known packer section names detected:")
        findings.extend(hits)

    # 2. Entry point section entropy
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = None
        for section in pe.sections:
            start = section.VirtualAddress
            end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
            if start <= ep < end:
                ep_section = section
                break
        if ep_section is not None:
            ep_name = ep_section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
            ep_ent = ep_section.get_entropy()
            if ep_ent > 7.0:
                flag = "[!!] VERY HIGH — strong packer indicator"
            elif ep_ent > 6.5:
                flag = "[!] HIGH — possible packer/protector"
            elif ep_ent > 6.0:
                flag = "ELEVATED — worth investigating"
            else:
                flag = "normal"
            findings.append(f"\nEntry point section: '{ep_name}'  entropy: {ep_ent:.4f}  ({flag})")
        else:
            findings.append("\n[!] Entry point does not fall within any section (suspicious)")
    except Exception as e:
        findings.append(f"\nEntry point check error: {e}")

    # 3. Overall high-entropy section count
    try:
        high = []
        for section in pe.sections:
            ent = section.get_entropy()
            sname = section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
            if ent > 6.5:
                high.append(f"  {sname:<12} {ent:.4f}")
        if high:
            findings.append(f"\nHigh-entropy sections ({len(high)}/{len(pe.sections)}):")
            findings.extend(high)
            if len(high) == len(pe.sections):
                findings.append("  [!] ALL sections are high-entropy — file is likely packed or encrypted")
        else:
            findings.append("\nNo high-entropy sections detected.")
    except Exception as e:
        findings.append(f"\nSection entropy check error: {e}")

    # 4. Very few sections combined with high entropy (common packer layout)
    if len(pe.sections) <= 3 and any("HIGH" in f or "VERY HIGH" in f for f in findings):
        findings.append(f"\n[!] Only {len(pe.sections)} section(s) — minimal section count is typical of packed binaries")

    if not any("[!" in f for f in findings):
        return "No packer indicators detected.\n\n" + '\n'.join(findings)

    return '\n'.join(findings)
