import datetime
import hashlib
import logging
import math
from collections import Counter, defaultdict

import pefile

try:
    from signify.authenticode.signed_file import SignedPEFile
    from signify.authenticode import AuthenticodeVerificationResult
    SIGNIFY_AVAILABLE = True
except ImportError:
    SIGNIFY_AVAILABLE = False

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
    '.winlice': 'WinLicense',
    '.enigma1': 'Enigma Protector', '.enigma2': 'Enigma Protector',
    '.shrink1': 'FSG',      '.shrink2': 'FSG',
    'pebundle': 'PEBundle',
    '.WISE':    'WISE Installer',
    '.packed':  'Generic Packer',
    '.svmp':    'SafeVM',
    'BeRoEXEP': 'BeRo Tiny PE Packer',
    '.boom':    'The Boomerang List Builder',
    'PEPACK!!': 'PEPack',
}

# Raw byte signatures embedded by packers / build tools.
# Each entry: (pattern, tool_name, category)
# category is one of: packer | protector | obfuscator | interpreter | installer | compiler
PACKER_BYTE_SIGS = [
    # ── Packers ───────────────────────────────────────────────────────────────
    (b'UPX!',                       'UPX',                 'packer'),
    (b'MPRESS1',                    'MPRESS',              'packer'),
    (b'FSG!',                       'FSG',                 'packer'),
    (b'MEW',                        'MEW',                 'packer'),
    (b'PEC2',                       'PECompact',           'packer'),
    (b'ASPack',                     'ASPack',              'packer'),
    (b'NsPacK',                     'NsPack',              'packer'),
    (b'RLPack',                     'RLPack',              'packer'),
    (b'ExeStealth',                 'ExeStealth',          'packer'),
    # ── Protectors ────────────────────────────────────────────────────────────
    (b'Silicon Realms Toolworks',   'Armadillo',           'protector'),
    (b'WinLicense',                 'WinLicense',          'protector'),
    (b'Obsidium',                   'Obsidium',            'protector'),
    (b'MoleBox',                    'MoleBox',             'protector'),
    (b'Enigma Protector',           'Enigma Protector',    'protector'),
    (b'The Enigma Protector',       'Enigma Protector',    'protector'),
    (b'EXECryptor',                 'EXECryptor',          'protector'),
    (b'Safengine',                  'Safengine',           'protector'),
    (b'Code Virtualizer',           'Code Virtualizer',    'protector'),
    (b'VMProtect',                  'VMProtect',           'protector'),
    # ── .NET obfuscators ──────────────────────────────────────────────────────
    (b'.NETReactor',                '.NET Reactor',        'obfuscator'),
    (b'ConfuserEx',                 'ConfuserEx',          'obfuscator'),
    (b'Dotfuscator',                'Dotfuscator',         'obfuscator'),
    (b'SmartAssembly',              'SmartAssembly',       'obfuscator'),
    (b'Eazfuscator',                'Eazfuscator',         'obfuscator'),
    (b'de4dot',                     'de4dot (unpacked)',   'obfuscator'),
    (b'Babel Obfuscator',           'Babel Obfuscator',    'obfuscator'),
    (b'ILProtector',                'ILProtector',         'obfuscator'),
    # ── Interpreted / compiled scripts ────────────────────────────────────────
    (b'AU3!',                       'AutoIt',              'interpreter'),
    (b'PyInstaller',                'PyInstaller',         'interpreter'),
    (b'py2exe',                     'py2exe',              'interpreter'),
    (b'cx_Freeze',                  'cx_Freeze',           'interpreter'),
    (b'This is a third-party',      'py2exe',              'interpreter'),
    # ── Compilers / runtimes (not packers, but useful context) ────────────────
    (b'Go build ID:',               'Go toolchain',        'compiler'),
    # ── Installers / SFX (may wrap malware) ───────────────────────────────────
    (b'NullsoftInst',               'NSIS Installer',      'installer'),
    (b'Inno Setup Setup Data',      'Inno Setup',          'installer'),
    (b'InnoSetupLdrWindow',         'Inno Setup',          'installer'),
    (b'WinRAR SFX',                 'WinRAR SFX',          'installer'),
    (b'7-Zip',                      '7-Zip SFX',           'installer'),
    (b'InstallShield',              'InstallShield',       'installer'),
    (b'Setup Factory',              'Setup Factory',       'installer'),
    (b'NSIS Error',                 'NSIS Installer',      'installer'),
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def pefile_subtool(sub_tool, file_path):
    """Dispatch to a pefile sub-tool. Returns a formatted string."""
    # codesign uses signify directly on the raw file — no pefile object needed.
    if sub_tool == 'codesign':
        return _codesign(file_path)

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
        elif sub_tool == 'timestamp':
            return _timestamp(pe)
        elif sub_tool == 'anti_vm':
            return _anti_vm(pe)
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
    """Identify packer/protector by signature, section names, import profile, and entropy."""
    raw = pe.__data__

    identified = {}  # name → set of evidence strings

    def record(name, evidence):
        identified.setdefault(name, set()).add(evidence)

    # ── 1. Raw byte signature scan ────────────────────────────────────────────
    for pattern, tool, _cat in PACKER_BYTE_SIGS:
        if pattern in raw:
            record(tool, f"byte signature {pattern!r}")

    # ── 2. Known packer section names ─────────────────────────────────────────
    section_names = []
    for section in pe.sections:
        sname = section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
        section_names.append(sname)
        if sname in PACKER_SECTIONS:
            record(PACKER_SECTIONS[sname], f"section name '{sname}'")

    # ── 3. Overlay signature ───────────────────────────────────────────────────
    try:
        overlay = pe.get_overlay()
        if overlay:
            for pattern, tool, _cat in PACKER_BYTE_SIGS:
                if pattern in overlay[:256]:
                    record(tool, f"overlay signature {pattern!r}")
    except Exception:
        pass

    # ── 4. Entry point section + entropy ──────────────────────────────────────
    ep_info = []
    ep_high_entropy = False
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = None
        for section in pe.sections:
            va = section.VirtualAddress
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if va <= ep < va + size:
                ep_section = section
                break
        if ep_section is not None:
            ep_name = ep_section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
            ep_ent = ep_section.get_entropy()
            if ep_ent > 7.0:
                ep_info.append(f"Entry point: section '{ep_name}'  entropy {ep_ent:.4f}  [!!] VERY HIGH")
                ep_high_entropy = True
            elif ep_ent > 6.5:
                ep_info.append(f"Entry point: section '{ep_name}'  entropy {ep_ent:.4f}  [!] HIGH")
                ep_high_entropy = True
            elif ep_ent > 6.0:
                ep_info.append(f"Entry point: section '{ep_name}'  entropy {ep_ent:.4f}  [~] ELEVATED")
            else:
                ep_info.append(f"Entry point: section '{ep_name}'  entropy {ep_ent:.4f}  (normal)")
        else:
            ep_info.append("[!] Entry point does not fall within any known section")
            ep_high_entropy = True
    except Exception as e:
        ep_info.append(f"Entry point check error: {e}")

    # ── 5. Section entropy profile ────────────────────────────────────────────
    entropy_lines = []
    high_count = 0
    try:
        for section in pe.sections:
            sn = section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
            ent = section.get_entropy()
            flag = '  [!] HIGH' if ent > 6.5 else ''
            if ent > 6.5:
                high_count += 1
            entropy_lines.append(f"  {sn:<12} {ent:.4f}{flag}")
    except Exception:
        pass

    all_high = high_count == len(pe.sections) and len(pe.sections) > 0

    # ── 6. Import profile ─────────────────────────────────────────────────────
    import_note = None
    try:
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            import_note = "[!] No import table — imports likely resolved at runtime (packed)"
        else:
            import_names = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        n = imp.name.decode('utf-8', errors='replace') if isinstance(imp.name, bytes) else str(imp.name)
                        import_names.append(n)
            loader_only = all(
                n in ('LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'ExitProcess')
                for n in import_names
            )
            if len(import_names) <= 4 and loader_only:
                import_note = (
                    f"[!] Only {len(import_names)} import(s): {', '.join(import_names)}"
                    " — minimal import table typical of packed binary"
                )
            elif len(import_names) == 0:
                import_note = "[!] Import table present but empty"
    except Exception:
        pass

    # ── Assemble output ───────────────────────────────────────────────────────
    lines = []

    if identified:
        names = sorted(identified)
        if len(names) == 1:
            lines.append(f"VERDICT: Packer / tool identified — {names[0]}")
        else:
            lines.append(f"VERDICT: Multiple packers / tools identified — {', '.join(names)}")
        lines.append("")
        lines.append("Evidence:")
        for name, evidences in sorted(identified.items()):
            for ev in sorted(evidences):
                lines.append(f"  [+] {name}: {ev}")
    elif ep_high_entropy or all_high or import_note:
        lines.append("VERDICT: Packed / obfuscated — packer not identified by signature")
    else:
        lines.append("VERDICT: No packer indicators detected")

    lines.append("")
    lines.append("── Section names ────────────────────────────────")
    lines.append(f"  {', '.join(section_names) if section_names else '(none)'}")

    lines.append("")
    lines.append("── Entropy profile ──────────────────────────────")
    lines.extend(entropy_lines)
    if all_high:
        lines.append("  [!] ALL sections are high-entropy — consistent with packed/encrypted content")
    if len(pe.sections) <= 3 and (ep_high_entropy or all_high):
        lines.append(f"  [!] Only {len(pe.sections)} section(s) — minimal section count typical of packers")

    lines.append("")
    lines.extend(ep_info)

    if import_note:
        lines.append("")
        lines.append("── Import profile ───────────────────────────────")
        lines.append(f"  {import_note}")

    return '\n'.join(lines)


# Known suspicious timestamp values seen in common malware / linker stubs.
_KNOWN_FAKE_TIMESTAMPS = {
    0x00000000: "zero — stripped or deliberately zeroed",
    0x2A425E19: "1992-06-19 — MSVC default stub timestamp (common in packed/hollowed PEs)",
    0x4CE78E6B: "2010-11-20 — widely reused fake timestamp across multiple malware families",
    0x53BF1423: "2014-07-11 — associated with Dridex and common packer stubs",
    0xFFFFFFFF: "0xFFFFFFFF — invalid sentinel value",
}


def _timestamp(pe):
    """Analyse the PE compile timestamp for anomalies."""
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
    except Exception as e:
        return f"Error reading timestamp: {e}"

    lines = [f"Timestamp (raw):  0x{ts:08x}"]

    if ts == 0:
        lines.append("Timestamp (UTC):  N/A (zeroed)")
        lines.append("\n[!] Timestamp is zero — stripped or deliberately wiped (common in packers/protectors)")
        return '\n'.join(lines)

    try:
        dt = datetime.datetime.utcfromtimestamp(ts)
    except (OSError, OverflowError, ValueError):
        lines.append("Timestamp (UTC):  INVALID (out-of-range value)")
        lines.append(f"\n[!] Timestamp 0x{ts:08x} cannot be converted to a valid date — likely forged")
        return '\n'.join(lines)

    now = datetime.datetime.utcnow()
    age = now - dt
    lines.append(f"Timestamp (UTC):  {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append(f"Age:              {age.days} days (~{age.days // 365} years)")
    lines.append("")

    flags = []

    # Future timestamp
    if dt > now:
        flags.append(f"[!] FUTURE timestamp — {(dt - now).days} days ahead of current time; "
                     "strong indicator of tampering or wrong system clock at build time")

    # Pre-PE-era (PE format introduced ~1993)
    elif dt < datetime.datetime(1993, 1, 1):
        flags.append(f"[!] PRE-1993 timestamp ({dt.year}) — PE format did not exist yet; "
                     "almost certainly forged or a known stub value")

    # Very old but plausible
    elif dt < datetime.datetime(2000, 1, 1):
        flags.append(f"[~] VERY OLD timestamp ({dt.year}) — unusually old; may be forged")

    # Known suspicious values
    if ts in _KNOWN_FAKE_TIMESTAMPS:
        flags.append(f"[!] Known suspicious value: {_KNOWN_FAKE_TIMESTAMPS[ts]}")

    if flags:
        lines.extend(flags)
    else:
        lines.append("No timestamp anomalies detected.")

    return '\n'.join(lines)


# Anti-VM / anti-sandbox string artifacts to look for in raw binary data.
# Grouped by hypervisor/sandbox for clear reporting.
_ANTI_VM_ARTIFACTS = {
    'VMware': [
        b'VMwareVMCI', b'vmci.sys', b'VMware', b'vmtoolsd', b'vmwaretray',
        b'vmacthlp', b'vmhgfs.sys', b'vmmouse.sys', b'vmrawdsk.sys',
        b'vmusbmouse.sys', b'vmvss.sys', b'vmscsi.sys', b'VMCI',
        b'vmware', b'.vmx', b'vmware-tray',
    ],
    'VirtualBox': [
        b'VBoxGuest', b'VBoxService', b'VBoxTray', b'VBoxSF',
        b'vboxguest', b'vboxsf', b'vboxmouse', b'vboxvideo',
        b'vboxdisp', b'VBoxSharedFolders', b'VBox', b'vbox',
        b'VBOX', b'VirtualBox',
    ],
    'QEMU / KVM': [
        b'qemu-ga', b'QEMU', b'qemu', b'virtio', b'VIRTIO',
        b'viostor', b'vioscsi', b'vioser',
    ],
    'Hyper-V': [
        b'vmbus', b'vmbusres', b'vmicheartbeat', b'vmicvss',
        b'vmicshutdown', b'vmicexchange', b'vmicrdv',
    ],
    'Sandbox / Analysis Tool': [
        b'SandboxStarter', b'sbiedll', b'SbieDll',
        b'api_log', b'dir_watch', b'pstorec',
        b'dbgview', b'wireshark', b'Wireshark',
        b'procmon', b'ProcessMonitor', b'filemon',
        b'regmon', b'idaq', b'idaq64', b'ollydbg',
        b'x64dbg', b'x32dbg', b'windbg',
        b'cuckoosandbox', b'cuckoo',
    ],
    'Known Sandbox File Paths / Names': [
        b'C:\\\\analysis\\\\', b'C:\\\\sandbox\\\\', b'C:\\\\cuckoo\\\\',
        b'sample.exe', b'malware.exe', b'virus.exe', b'test.exe',
        b'\\\\WINDOWS\\\\system32\\\\drivers\\\\vmmouse',
        b'HARDWARE\\\\ACPI\\\\DSDT\\\\VBOX',
        b'HARDWARE\\\\ACPI\\\\DSDT\\\\VMWARE',
    ],
}


def _anti_vm(pe):
    """Scan raw binary data for known anti-VM / anti-sandbox string artifacts."""
    try:
        raw = pe.__data__
    except Exception as e:
        return f"Error reading PE data: {e}"

    found = defaultdict(list)
    for category, patterns in _ANTI_VM_ARTIFACTS.items():
        for pattern in patterns:
            if pattern in raw:
                found[category].append(pattern.decode('utf-8', errors='replace'))

    if not found:
        return "No anti-VM / anti-sandbox artifacts detected in binary data."

    total = sum(len(v) for v in found.values())
    lines = [f"Anti-VM / anti-sandbox artifacts detected ({total} total):\n"]
    for category in sorted(found):
        lines.append(f"[{category}]")
        for artifact in sorted(set(found[category])):
            lines.append(f"  {artifact}")
        lines.append("")

    lines.append("[!] Presence of these strings suggests the binary may attempt to detect or evade")
    lines.append("    virtualised / sandboxed analysis environments.")
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Authenticode / code signing analysis
# ---------------------------------------------------------------------------

def _codesign(file_path: str) -> str:
    """
    Parse and verify the Authenticode signature embedded in a PE file.

    Reports:
      - Signed / unsigned / invalid verdict
      - Certificate chain (subject, issuer, serial, validity period, thumbprint)
      - Countersignature (timestamp authority + signing time) when present
      - Whether the signature verification passes against Microsoft's trusted roots

    Uses the 'signify' library.  If signify is not installed, returns a
    helpful install hint.
    """
    if not SIGNIFY_AVAILABLE:
        return "signify is not installed. Run: pip install signify"

    try:
        with open(file_path, 'rb') as fh:
            pe = SignedPEFile(fh)
            result, exc = pe.explain_verify()
            signatures = list(pe.iter_embedded_signatures())
    except Exception as e:
        logger.exception(e)
        return f"Error analysing Authenticode signature: {e}"

    lines = []

    # ── Overall verdict ───────────────────────────────────────────────────
    verdict_map = {
        AuthenticodeVerificationResult.OK:             "VALID   — signature verifies against trusted roots",
        AuthenticodeVerificationResult.NOT_SIGNED:     "UNSIGNED — no Authenticode signature found",
        AuthenticodeVerificationResult.CERTIFICATE_ERROR: "INVALID — certificate chain error",
        AuthenticodeVerificationResult.VERIFY_ERROR:   "INVALID — signature verification failed",
        AuthenticodeVerificationResult.PARSE_ERROR:    "ERROR   — signature could not be parsed",
    }
    verdict_str = verdict_map.get(result, f"UNKNOWN ({result})")
    lines.append(f"Verdict: {verdict_str}")
    if exc and result != AuthenticodeVerificationResult.NOT_SIGNED:
        lines.append(f"Detail:  {exc}")
    lines.append("")

    if not signatures:
        return '\n'.join(lines)

    for sig_idx, sig in enumerate(signatures):
        lines.append(f"── Signature {sig_idx + 1} ──────────────────────────────────────")
        try:
            # Signing certificate
            cert = sig.signer_info.signing_certificate
            if cert:
                lines.append(f"  Subject:     {cert.subject.dn}")
                lines.append(f"  Issuer:      {cert.issuer.dn}")
                lines.append(f"  Serial:      {cert.serial_number}")
                lines.append(f"  Not Before:  {cert.valid_from}")
                lines.append(f"  Not After:   {cert.valid_to}")
                sha1 = cert.sha1_fingerprint
                if sha1:
                    lines.append(f"  Thumbprint:  {sha1.hex().upper()}")
        except Exception as e:
            lines.append(f"  [!] Could not extract signing certificate: {e}")

        # Certificate chain
        try:
            chain = sig.signed_data.cert_store.certificates
            if chain:
                lines.append(f"\n  Certificate chain ({len(list(chain))} cert(s)):")
                for c in chain:
                    lines.append(f"    • {c.subject.dn}")
        except Exception:
            pass

        # Countersignature / timestamp
        try:
            for cs in sig.signer_info.counter_signers:
                lines.append("\n  Countersignature (timestamp authority):")
                try:
                    ts_cert = cs.signing_certificate
                    if ts_cert:
                        lines.append(f"    TSA Subject: {ts_cert.subject.dn}")
                except Exception:
                    pass
                try:
                    signing_time = cs.signing_time
                    if signing_time:
                        lines.append(f"    Signing time: {signing_time} UTC")
                except Exception:
                    pass
        except Exception:
            pass

        lines.append("")

    return '\n'.join(lines)
