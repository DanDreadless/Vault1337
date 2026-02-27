import hashlib
import logging
import pefile

logger = logging.getLogger(__name__)

SUSPICIOUS_APIS = {
    'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
    'CreateRemoteThread', 'NtUnmapViewOfSection', 'RtlDecompressBuffer',
    'LoadLibrary', 'GetProcAddress', 'IsDebuggerPresent', 'OpenProcess',
}


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
                        found.append(f"  {lib} -> {name}")
        if not found:
            return "No suspicious imports detected."
        return "Suspicious imports found:\n" + '\n'.join(found)
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
