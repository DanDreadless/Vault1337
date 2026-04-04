"""
.NET assembly analysis tool using dnfile.

Sub-tools:
  metadata   — assembly identity, version, target framework, MVID
  imports    — referenced external assemblies (MemberRef table)
  strings    — user strings from the #US heap
  resources  — embedded managed resources
  obfuscator — heuristic detection of common .NET protectors
"""

import logging
import os

logger = logging.getLogger(__name__)

_MAX_SIZE = 50 * 1024 * 1024  # 50 MB cap

try:
    import dnfile
    DNFILE_AVAILABLE = True
except ImportError:
    DNFILE_AVAILABLE = False


def dotnet_subtool(file_path: str, sub_tool: str) -> str:
    """Dispatch a dnfile sub-tool against a .NET PE file."""
    if not DNFILE_AVAILABLE:
        return '[!] dnfile is not installed. Run: pip install dnfile'

    if not os.path.isfile(file_path):
        return '[!] File not found.'

    file_size = os.path.getsize(file_path)
    if file_size > _MAX_SIZE:
        return f'[!] File too large for .NET analysis ({file_size // (1024*1024)} MB > 50 MB limit).'

    dispatch = {
        'metadata':   _metadata,
        'imports':    _imports,
        'strings':    _strings,
        'resources':  _resources,
        'obfuscator': _obfuscator,
    }

    if sub_tool not in dispatch:
        return f"[!] Unknown sub-tool '{sub_tool}'. Available: {', '.join(dispatch)}"

    try:
        pe = dnfile.dnPE(file_path)
    except Exception as exc:
        logger.warning('dnfile failed to parse %s: %s', file_path, exc)
        return f'[!] Failed to parse .NET assembly: {exc}'

    if pe.net is None or pe.net.mdtables is None:
        return (
            '[!] No .NET metadata found in this file.\n'
            'The file may be a native PE, an unpacked stub, or have stripped/corrupted CLR headers.\n'
            'Confirm the sample is a managed assembly before using the .NET tool.'
        )

    try:
        return dispatch[sub_tool](pe, file_path)
    except Exception as exc:
        logger.exception('dotnet_tool %s error on %s', sub_tool, file_path)
        return f'[!] Error running {sub_tool}: {exc}'


# ── helpers ──────────────────────────────────────────────────────────────────

def _get_net_meta(pe) -> object | None:
    """Return the mdtAssembly row if present, else None."""
    try:
        tbl = pe.net.mdtables.Assembly
        if tbl and tbl.num_rows > 0:
            return tbl.rows[0]
    except Exception:
        pass
    return None


def _get_custom_attrs(pe, attr_name: str) -> list[str]:
    """
    Walk CustomAttribute table looking for a specific attribute class name.
    Returns list of decoded blob values where found.
    """
    results = []
    try:
        tbl = pe.net.mdtables.CustomAttribute
        if not tbl:
            return results
        for row in tbl.rows:
            try:
                type_name = str(getattr(row, 'Type', '') or '')
                if attr_name.lower() in type_name.lower():
                    blob = getattr(row, 'Value', b'')
                    if isinstance(blob, (bytes, bytearray)) and len(blob) > 2:
                        # Skip the prolog (0x0001) and try to decode the string
                        try:
                            text = blob[2:].decode('utf-8', errors='replace').strip('\x00')
                            if text:
                                results.append(text)
                        except Exception:
                            pass
            except Exception:
                continue
    except Exception:
        pass
    return results


# ── sub-tool implementations ──────────────────────────────────────────────────

def _metadata(pe, _file_path: str) -> str:
    lines = ['── .NET Assembly Metadata ──']

    # Assembly identity
    row = _get_net_meta(pe)
    if row:
        name = getattr(row, 'Name', 'unknown')
        ver = getattr(row, 'MajorVersion', '?')
        minor = getattr(row, 'MinorVersion', '?')
        build = getattr(row, 'BuildNumber', '?')
        rev = getattr(row, 'Revision', '?')
        lines.append(f'Assembly Name : {name}')
        lines.append(f'Version       : {ver}.{minor}.{build}.{rev}')
        culture = getattr(row, 'Culture', '') or 'neutral'
        lines.append(f'Culture       : {culture}')
        flags = getattr(row, 'Flags', 0)
        lines.append(f'Flags         : 0x{flags:08X}')
    else:
        lines.append('[!] No Assembly table row found — may not be a valid .NET assembly.')

    # Module MVID
    try:
        mod_tbl = pe.net.mdtables.Module
        if mod_tbl and mod_tbl.num_rows > 0:
            mod = mod_tbl.rows[0]
            mvid = getattr(mod, 'Mvid', None)
            if mvid:
                lines.append(f'MVID          : {mvid}')
    except Exception:
        pass

    # Target framework attribute
    tf = _get_custom_attrs(pe, 'TargetFrameworkAttribute')
    if tf:
        lines.append(f'Target FW     : {tf[0]}')

    # Runtime version from CLI header
    try:
        clr = pe.net.Flags
        lines.append(f'CLR Flags     : 0x{clr:08X}')
    except Exception:
        pass

    try:
        major = pe.net.MajorRuntimeVersion
        minor = pe.net.MinorRuntimeVersion
        lines.append(f'Runtime ver   : {major}.{minor}')
    except Exception:
        pass

    return '\n'.join(lines)


def _imports(pe, _file_path: str) -> str:
    """List external assembly references (AssemblyRef table)."""
    lines = ['── Referenced Assemblies ──']
    try:
        tbl = pe.net.mdtables.AssemblyRef
        if not tbl or tbl.num_rows == 0:
            return '\n'.join(lines) + '\nNone found.'
        for row in tbl.rows:
            name = getattr(row, 'Name', '?')
            ver_major = getattr(row, 'MajorVersion', '?')
            ver_minor = getattr(row, 'MinorVersion', '?')
            lines.append(f'  {name} v{ver_major}.{ver_minor}')
    except Exception as exc:
        lines.append(f'[!] Error reading AssemblyRef table: {exc}')

    # Also list MemberRef (imported types/methods) — top 200
    member_names: set[str] = set()
    try:
        tbl = pe.net.mdtables.MemberRef
        if tbl:
            for row in tbl.rows:
                class_ref = getattr(row, 'Class', None)
                member_name = str(getattr(row, 'Name', '') or '')
                if class_ref:
                    class_name = str(getattr(class_ref, 'Name', '') or '')
                    ns = str(getattr(class_ref, 'Namespace', '') or '')
                    if ns:
                        member_names.add(f'{ns}.{class_name}::{member_name}')
                    elif class_name:
                        member_names.add(f'{class_name}::{member_name}')
    except Exception:
        pass

    if member_names:
        lines.append('')
        lines.append('── Imported Members (sample) ──')
        for m in sorted(member_names)[:200]:
            lines.append(f'  {m}')
        if len(member_names) > 200:
            lines.append(f'  ... and {len(member_names) - 200} more')

    return '\n'.join(lines)


def _strings(pe, _file_path: str) -> str:
    """Extract user strings from the #US (user strings) heap."""
    lines = ['── .NET User Strings (#US heap) ──']
    try:
        us = pe.net.user_strings
        if not us:
            return '\n'.join(lines) + '\nNo #US heap found.'
        strings = []
        for s in us:
            # dnfile wraps each entry; the string value is in .value
            val = getattr(s, 'value', None)
            if val and len(val) >= 4:
                strings.append(val)
        if not strings:
            lines.append('No user strings found.')
        else:
            lines.append(f'Count: {len(strings)}')
            lines.append('')
            for s in strings[:500]:
                lines.append(f'  {s}')
            if len(strings) > 500:
                lines.append(f'  ... ({len(strings) - 500} more truncated)')
    except Exception as exc:
        lines.append(f'[!] Error reading #US heap: {exc}')
    return '\n'.join(lines)


def _resources(pe, _file_path: str) -> str:
    """List embedded managed resources."""
    lines = ['── Managed Resources ──']
    try:
        tbl = pe.net.mdtables.ManifestResource
        if not tbl or tbl.num_rows == 0:
            return '\n'.join(lines) + '\nNone found.'
        for row in tbl.rows:
            name = getattr(row, 'Name', '?')
            offset = getattr(row, 'Offset', 0)
            flags = getattr(row, 'Flags', 0)
            visibility = 'Public' if (flags & 0x7) == 1 else 'Private'
            lines.append(f'  {name}  offset=0x{offset:08X}  visibility={visibility}')
    except Exception as exc:
        lines.append(f'[!] Error reading ManifestResource table: {exc}')
    return '\n'.join(lines)


def _obfuscator(pe, _file_path: str) -> str:
    """
    Heuristic detection of .NET obfuscators / protectors.

    Checks for known metadata artefacts left by common tools:
    ConfuserEx, SmartAssembly, .NET Reactor, Dotfuscator, Eazfuscator,
    DNGuard, de4dot (deobfuscator traces), Babel, Phoenix, etc.
    """
    lines = ['── .NET Obfuscator / Protector Detection ──']
    findings: list[str] = []

    # ── Check assembly-level custom attributes for protector markers ──
    PROTECTOR_ATTRS = {
        'ConfusedByAttribute':          'ConfuserEx / Confuser',
        'ObfuscatedByGoliath':          'Goliath .NET Obfuscator',
        'SmartAssembly':                'SmartAssembly',
        'Dotfuscator':                  'Dotfuscator',
        'NativeCodeAttribute':          '.NET Reactor (native stub)',
        'ObfuscationAttribute':         'Standard ObfuscationAttribute (may be legit)',
        'AssemblyProtectedAttribute':   'Eazfuscator / similar',
        'KoiVM':                        'KoiVM Virtualizer',
        'DoubleAgent':                  'DoubleAgent protector',
    }
    try:
        ca_tbl = pe.net.mdtables.CustomAttribute
        if ca_tbl:
            for row in ca_tbl.rows:
                type_str = str(getattr(row, 'Type', '') or '')
                for marker, label in PROTECTOR_ATTRS.items():
                    if marker.lower() in type_str.lower():
                        findings.append(f'[ATTR] {label}  (attribute: {marker})')
    except Exception:
        pass

    # ── Check module name for known markers ──
    MODULE_MARKERS = {
        '#Zing':        'ConfuserEx (module renamed to #Zing)',
        'koi':          'KoiVM (module/stream name)',
        'Babel':        'Babel Obfuscator',
        'Phoenix':      'Phoenix Protector',
    }
    try:
        mod_tbl = pe.net.mdtables.Module
        if mod_tbl and mod_tbl.num_rows > 0:
            mod_name = str(getattr(mod_tbl.rows[0], 'Name', '') or '')
            for marker, label in MODULE_MARKERS.items():
                if marker.lower() in mod_name.lower():
                    findings.append(f'[MODULE] {label}  (module name: {mod_name})')
    except Exception:
        pass

    # ── Check metadata stream names ──
    STREAM_MARKERS = {
        '#Zing': 'ConfuserEx (renamed metadata stream)',
        '#-':    'Unoptimised metadata stream (possible repacking/obfuscation)',
    }
    try:
        for stream in pe.net.metadata.streams_list:
            sname = getattr(stream, 'name', '') or ''
            for marker, label in STREAM_MARKERS.items():
                if marker in sname:
                    findings.append(f'[STREAM] {label}  (stream: {sname})')
    except Exception:
        pass

    # ── Heuristic: suspicious TypeDef names (single char / random) ──
    try:
        tbl = pe.net.mdtables.TypeDef
        if tbl:
            total = tbl.num_rows
            short_names = sum(
                1 for row in tbl.rows
                if len(str(getattr(row, 'Name', '') or '')) == 1
            )
            if total > 5 and short_names / total > 0.5:
                findings.append(
                    f'[HEURISTIC] {short_names}/{total} TypeDef names are single characters '
                    f'— consistent with name obfuscation'
                )
    except Exception:
        pass

    # ── Heuristic: no symbol names in MethodDef (all numeric or empty) ──
    try:
        tbl = pe.net.mdtables.MethodDef
        if tbl and tbl.num_rows > 0:
            empty = sum(
                1 for row in tbl.rows
                if not str(getattr(row, 'Name', '') or '').strip()
            )
            if empty / tbl.num_rows > 0.8:
                findings.append(
                    f'[HEURISTIC] {empty}/{tbl.num_rows} MethodDef entries have no name '
                    f'— heavy obfuscation likely'
                )
    except Exception:
        pass

    if findings:
        for f in findings:
            lines.append(f'  {f}')
    else:
        lines.append('  No known obfuscator markers detected.')

    return '\n'.join(lines)
