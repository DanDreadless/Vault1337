import hashlib
import logging
import lief
import math
from collections import Counter, defaultdict
from tabulate import tabulate
from datetime import datetime

logger = logging.getLogger(__name__)


# Suspicious ELF dynamic symbols mapped to category.
ELF_SUSPICIOUS_SYMBOLS = {
    # ── Execution ────────────────────────────────────────────────────────────
    'execve':       'Execution',
    'execl':        'Execution',
    'execle':       'Execution',
    'execv':        'Execution',
    'execvp':       'Execution',
    'execlp':       'Execution',
    'system':       'Execution',
    'popen':        'Execution',
    'fork':         'Execution',
    'vfork':        'Execution',
    'clone':        'Execution',
    # ── Network ──────────────────────────────────────────────────────────────
    'socket':       'Network',
    'connect':      'Network',
    'bind':         'Network',
    'listen':       'Network',
    'accept':       'Network',
    'accept4':      'Network',
    'recv':         'Network',
    'recvfrom':     'Network',
    'recvmsg':      'Network',
    'send':         'Network',
    'sendto':       'Network',
    'sendmsg':      'Network',
    'getaddrinfo':  'Network',
    # ── Privilege Escalation ─────────────────────────────────────────────────
    'setuid':       'Privilege Escalation',
    'setgid':       'Privilege Escalation',
    'setreuid':     'Privilege Escalation',
    'setregid':     'Privilege Escalation',
    'setresuid':    'Privilege Escalation',
    'setresgid':    'Privilege Escalation',
    'chmod':        'Privilege Escalation',
    'fchmod':       'Privilege Escalation',
    'chown':        'Privilege Escalation',
    'capset':       'Privilege Escalation',
    # ── Anti-Analysis / Injection ────────────────────────────────────────────
    'ptrace':       'Anti-Analysis / Injection',
    'mprotect':     'Anti-Analysis / Injection',
    'mmap':         'Anti-Analysis / Injection',
    'mmap2':        'Anti-Analysis / Injection',
    'process_vm_readv':  'Anti-Analysis / Injection',
    'process_vm_writev': 'Anti-Analysis / Injection',
    # ── Dynamic Loading ───────────────────────────────────────────────────────
    'dlopen':       'Dynamic Loading',
    'dlsym':        'Dynamic Loading',
    'dlmopen':      'Dynamic Loading',
    # ── Rootkit / File Hiding ─────────────────────────────────────────────────
    'getdents':     'Rootkit / File Hiding',
    'getdents64':   'Rootkit / File Hiding',
    'readdir':      'Rootkit / File Hiding',
    'inotify_add_watch': 'Surveillance',
    'fanotify_init':     'Surveillance',
}

# Known ELF packer / obfuscator section names.
ELF_PACKER_SECTIONS = {
    'upx':     'UPX',
    '.upx':    'UPX',
    'upx0':    'UPX',
    'upx1':    'UPX',
    '.packed': 'Generic Packer',
    '.vmp0':   'VMProtect',
    '.vmp1':   'VMProtect',
}


def calculate_entropy(data):
    """Calculate the entropy of a block of data."""
    if not data:
        return 0

    byte_counts = Counter(data)
    total_bytes = len(data)

    entropy = 0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy

def calculate_section_entropy(binary):
    sections_entropy = {}

    for section in binary.sections:
        entropy = calculate_entropy(section.content)
        sections_entropy[section.name] = entropy

    return sections_entropy

def lief_parse_subtool(sub_tool, file_path):
    try:
        binary = lief.parse(file_path)
        if binary is None:
            return f"Error parsing the binary: {str(file_path)}"

        pe_header = None

        # --- PE-specific sub-tools ---
        if sub_tool == 'dos_header':
            dh = binary.dos_header
            pe_header = "\n".join([
                f"Magic:                    0x{dh.magic:04x}",
                f"Used bytes in last page:  {dh.used_bytes_in_last_page}",
                f"File size in pages:       {dh.file_size_in_pages}",
                f"Relocations:              {dh.numberof_relocation}",
                f"Header size (paragraphs): {dh.header_size_in_paragraphs}",
                f"Min extra paragraphs:     {dh.minimum_extra_paragraphs}",
                f"Max extra paragraphs:     {dh.maximum_extra_paragraphs}",
                f"Initial SS:               0x{dh.initial_relative_ss:04x}",
                f"Initial SP:               0x{dh.initial_sp:04x}",
                f"Checksum:                 0x{dh.checksum:04x}",
                f"Initial IP:               0x{dh.initial_ip:04x}",
                f"Initial CS:               0x{dh.initial_relative_cs:04x}",
                f"Relocation table offset:  0x{dh.addressof_relocation_table:04x}",
                f"OEM ID:                   0x{dh.oem_id:04x}",
                f"OEM info:                 0x{dh.oem_info:04x}",
                f"New EXE header address:   0x{dh.addressof_new_exeheader:08x}",
            ])
        elif sub_tool == 'rich_header':
            rh = binary.rich_header
            if rh is None:
                pe_header = "No Rich Header found."
            else:
                lines = [f"Key: 0x{rh.key:08x}", "", f"{'Comp ID':<10} {'Build ID':<10} Count"]
                lines.append("-" * 35)
                for entry in rh.entries:
                    lines.append(f"0x{entry.id:04x}     0x{entry.build_id:04x}     {entry.count}")
                pe_header = "\n".join(lines)
        elif sub_tool == 'pe_header':
            h = binary.header
            pe_header = "\n".join([
                f"Machine:               {h.machine}",
                f"Sections:              {h.numberof_sections}",
                f"Timestamp:             {h.time_date_stamps}",
                f"Symbol table offset:   {h.pointerto_symbol_table}",
                f"Symbols:               {h.numberof_symbols}",
                f"Optional header size:  {h.sizeof_optional_header}",
                f"Characteristics:       0x{h.characteristics:04x}",
            ])
        elif sub_tool == 'entrypoint':
            pe_header = f"Entry Point: 0x{binary.entrypoint:08x}"
        elif sub_tool == 'sections':
            result = []
            headers = ["Name", "Content", "Virtual Address", "Virtual Size", "Offset", "Size"]

            for section in binary.sections:
                name = section.name
                contentn = section.content
                virtual_address = section.virtual_address
                virtual_size = section.virtual_size
                offset = section.offset
                size = section.size
                result.append([name, contentn, virtual_address, virtual_size, offset, size])
            pe_header = tabulate(result, headers=headers, tablefmt="grid")
        elif sub_tool == 'imports':
            result = []
            if not binary.has_imports:
                pe_header = "No imports found"
            else:
                pe_header = f"Found {len(binary.imports)} imported libraries\n\n"

                headers = ["Library", "Function Name", "Address", "Ordinal"]

                for library in binary.imports:
                    lib_name = library.name
                    for entry in library.entries:
                        func_name = entry.name if entry.name else "N/A"
                        address = entry.iat_address
                        ordinal = entry.ordinal if entry.is_ordinal else "N/A"
                        result.append([lib_name, func_name, address, ordinal])

                pe_header += tabulate(result, headers=headers, tablefmt="grid")

        elif sub_tool == 'sigcheck':
            try:
                pe_header = ""
                signature = binary.signatures[0]
                for crt in signature.certificates:
                    pe_header += str(crt) + "\n"

                authentihash = signature.content_info.digest.hex()
                pe_header += f"Authenticode Hash: {authentihash}"

                signer_info = signature.signers[0]
                pe_header += f"\n\nSigner Info: {signer_info}"
                verified = binary.verify_signature()
                pe_header += f"\n\nSignature Verification: {verified}"
            except Exception as e:
                pe_header = f"Binary is not signed {str(e)}"

        elif sub_tool == 'checkentropy':
            pe_header = ""
            result = []
            headers = ["Section", "Entropy"]
            section_entropies = calculate_section_entropy(binary)
            for section_name, entropy in section_entropies.items():
                result.append([section_name, entropy])
            pe_header += tabulate(result, headers=headers, tablefmt="grid")

        elif sub_tool == 'exports':
            if not isinstance(binary, lief.PE.Binary):
                pe_header = "Error: File is not a PE binary."
            else:
                try:
                    if not binary.has_exports:
                        pe_header = "No exports found."
                    else:
                        exp = binary.exports
                        result = []
                        headers = ["Ordinal", "RVA", "Name", "Forward"]
                        for entry in exp.entries:
                            name = entry.name if entry.name else "(unnamed)"
                            rva = hex(entry.address) if entry.address else "N/A"
                            forward = ""
                            if entry.is_extern:
                                try:
                                    fi = entry.forward_information
                                    forward = f"{fi.library}.{fi.function}"
                                except Exception:
                                    forward = "(forwarded)"
                            result.append([entry.ordinal, rva, name, forward])
                        header = (
                            f"Export DLL Name: {exp.name}\n"
                            f"Ordinal Base:    {exp.ordinal_base}\n"
                            f"Total Exports:   {len(result)}\n\n"
                        )
                        pe_header = header + tabulate(result, headers=headers, tablefmt="grid")
                except Exception as e:
                    pe_header = f"Error reading exports: {str(e)}"

        # --- New PE sub-tools ---
        elif sub_tool == 'imphash':
            if not isinstance(binary, lief.PE.Binary):
                pe_header = "Error: File is not a PE binary."
            else:
                h = None
                try:
                    # PE.Binary.get_imphash() was removed in LIEF 0.14+
                    h = binary.get_imphash()
                except AttributeError:
                    pe_header = "Import hash not available via LIEF 0.14+. Use the PE File tool's Import Hash sub-tool instead."
                except Exception as e:
                    pe_header = f"Error computing imphash: {str(e)}"
                if h is not None:
                    pe_header = f"Import Hash (imphash): {h}" if h else "No import hash available (no imports or empty)."

        elif sub_tool == 'overlay':
            if not isinstance(binary, lief.PE.Binary):
                pe_header = "Error: File is not a PE binary."
            else:
                try:
                    overlay = bytes(binary.overlay)
                    if not overlay:
                        pe_header = "No overlay detected."
                    else:
                        pe_header = (
                            f"Overlay size: {len(overlay)} bytes\n"
                            f"First 64 bytes (hex): {overlay[:64].hex()}"
                        )
                except Exception as e:
                    pe_header = f"Error checking overlay: {str(e)}"

        elif sub_tool == 'rich_hash':
            if not isinstance(binary, lief.PE.Binary):
                pe_header = "Error: File is not a PE binary."
            else:
                try:
                    if binary.rich_header is None:
                        pe_header = "No Rich Header found."
                    else:
                        data = b''
                        for entry in binary.rich_header.entries:
                            data += int(entry.id).to_bytes(4, 'little') + int(entry.count).to_bytes(4, 'little')
                        pe_header = f"Rich Header Hash (MD5): {hashlib.md5(data).hexdigest()}"
                except Exception as e:
                    pe_header = f"Error computing rich header hash: {str(e)}"

        # --- ELF sub-tools ---
        elif sub_tool == 'elf_header':
            if not isinstance(binary, lief.ELF.Binary):
                pe_header = "Error: File is not an ELF binary."
            else:
                h = binary.header
                pe_header = (
                    f"Entry Point:       0x{binary.entrypoint:016x}\n"
                    f"Architecture:      {h.machine_type}\n"
                    f"File Type:         {h.file_type}\n"
                    f"OS/ABI:            {h.identity_os_abi}\n"
                    f"Sections:          {len(binary.sections)}\n"
                    f"Segments:          {len(binary.segments)}\n"
                )

        elif sub_tool == 'elf_sections':
            if not isinstance(binary, lief.ELF.Binary):
                pe_header = "Error: File is not an ELF binary."
            else:
                result = []
                headers = ["Name", "Type", "Size", "Offset", "Flags", "Entropy"]
                for section in binary.sections:
                    data = bytes(section.content)
                    entropy = calculate_entropy(data) if data else 0.0
                    result.append([
                        section.name,
                        str(section.type),
                        section.size,
                        section.offset,
                        str(section.flags),
                        f"{entropy:.4f}",
                    ])
                pe_header = tabulate(result, headers=headers, tablefmt="grid")

        elif sub_tool == 'elf_symbols':
            if not isinstance(binary, lief.ELF.Binary):
                pe_header = "Error: File is not an ELF binary."
            else:
                result = []
                headers = ["Name", "Type", "Binding", "Value"]
                for sym in binary.dynamic_symbols:
                    result.append([sym.name, str(sym.type), str(sym.binding), hex(sym.value)])
                if not result:
                    pe_header = "No dynamic symbols found."
                else:
                    pe_header = tabulate(result, headers=headers, tablefmt="grid")

        elif sub_tool == 'elf_suspicious':
            if not isinstance(binary, lief.ELF.Binary):
                pe_header = "Error: File is not an ELF binary."
            else:
                pe_header = _elf_suspicious(binary)

        elif sub_tool == 'elf_packer':
            if not isinstance(binary, lief.ELF.Binary):
                pe_header = "Error: File is not an ELF binary."
            else:
                pe_header = _elf_packer(binary)

        elif sub_tool == 'elf_segments':
            if not isinstance(binary, lief.ELF.Binary):
                pe_header = "Error: File is not an ELF binary."
            else:
                pe_header = _elf_segments(binary)

        elif sub_tool == 'elf_info':
            if not isinstance(binary, lief.ELF.Binary):
                pe_header = "Error: File is not an ELF binary."
            else:
                pe_header = _elf_info(binary)

        else:
            return f"Error: Invalid subtool: {sub_tool}"

        if pe_header:
            return pe_header
        else:
            return f"Failed to retrieve data for sub-tool: {sub_tool}"

    except Exception as e:
        logger.exception(e)
        return f"Error: {str(e)}"


# ── ELF helper functions ──────────────────────────────────────────────────────

def _elf_suspicious(binary):
    """Flag suspicious dynamic symbols in an ELF binary, grouped by category."""
    found = []
    for sym in binary.dynamic_symbols:
        name = sym.name
        if name in ELF_SUSPICIOUS_SYMBOLS:
            found.append((ELF_SUSPICIOUS_SYMBOLS[name], name))

    if not found:
        return "No suspicious symbols detected."

    by_cat = defaultdict(list)
    for category, name in found:
        by_cat[category].append(f"  {name}")

    lines = [f"Suspicious symbols found ({len(found)} total):\n"]
    for cat in sorted(by_cat):
        lines.append(f"[{cat}]")
        lines.extend(by_cat[cat])
        lines.append("")
    return '\n'.join(lines)


def _elf_packer(binary):
    """Detect packer/obfuscation indicators in an ELF binary."""
    findings = []

    # 1. Known packer section names
    hits = []
    for section in binary.sections:
        name = section.name.lower().rstrip('\x00')
        if name in ELF_PACKER_SECTIONS:
            hits.append(f"  '{section.name}' → {ELF_PACKER_SECTIONS[name]}")
    if hits:
        findings.append("[!] Known packer section names detected:")
        findings.extend(hits)

    # 2. UPX magic string in raw content (b"UPX!")
    try:
        for section in binary.sections:
            data = bytes(section.content)
            if b'UPX!' in data:
                findings.append(f"[!] UPX magic 'UPX!' found in section '{section.name}'")
                break
    except Exception as e:
        findings.append(f"UPX magic check error: {e}")

    # 3. Section entropy analysis
    try:
        high = []
        total = 0
        for section in binary.sections:
            if section.size == 0:
                continue
            total += 1
            data = bytes(section.content)
            ent = calculate_entropy(data)
            if ent > 6.5:
                high.append(f"  {section.name:<20} {ent:.4f}")
        if high:
            findings.append(f"\nHigh-entropy sections ({len(high)}/{total}):")
            findings.extend(high)
            if total > 0 and len(high) == total:
                findings.append("  [!] ALL sections are high-entropy — file is likely packed or encrypted")
        else:
            findings.append("\nNo high-entropy sections detected.")
    except Exception as e:
        findings.append(f"\nSection entropy check error: {e}")

    # 4. Missing standard sections (.text, .data)
    section_names = {s.name for s in binary.sections}
    missing = [n for n in ('.text', '.data') if n not in section_names]
    if missing:
        findings.append(f"\n[!] Standard sections missing: {', '.join(missing)} — typical of packed ELF")

    # 5. Very few sections with high entropy
    if len([s for s in binary.sections if s.size > 0]) <= 3 and any('[!]' in f for f in findings):
        findings.append(f"\n[!] Only {len(binary.sections)} section(s) — minimal count is typical of packed ELF")

    if not findings:
        return "No packer indicators detected."
    if not any('[!]' in f for f in findings):
        return "No packer indicators detected.\n\n" + '\n'.join(findings)
    return '\n'.join(findings)


def _elf_segments(binary):
    """List ELF program headers (segments) with type, flags, addresses and sizes."""
    segments = list(binary.segments)
    if not segments:
        return "No segments found (segment table may be stripped)."

    result = []
    headers = ["#", "Type", "Flags", "Virtual Address", "File Offset", "File Size", "Mem Size", "Align"]
    notes = []

    for i, seg in enumerate(segments):
        seg_type = str(seg.type).split('.')[-1]  # strip lief.ELF.SEGMENT_TYPES. prefix
        flags = str(seg.flags)
        result.append([
            i,
            seg_type,
            flags,
            f"0x{seg.virtual_address:08x}",
            f"0x{seg.file_offset:08x}",
            seg.physical_size,
            seg.virtual_size,
            f"0x{seg.alignment:x}",
        ])

        # Flag suspicious segment characteristics
        if seg_type == 'PT_NOTE':
            notes.append(f"  [~] Segment {i} is PT_NOTE — sometimes abused for ELF header confusion attacks")
        if seg_type == 'PT_LOAD' and seg.flags and 'W' in flags and 'X' in flags:
            notes.append(f"  [!] Segment {i} is PT_LOAD with Write+Execute (W+X) permissions — suspicious")

    output = tabulate(result, headers=headers, tablefmt="grid")
    if notes:
        output += "\n\nNotes:\n" + '\n'.join(notes)
    return output


def _elf_info(binary):
    """Report ELF binary metadata: stripped status, linking type, interpreter."""
    lines = []

    # Stripped detection: .symtab presence
    section_names = {s.name for s in binary.sections}
    has_symtab = '.symtab' in section_names
    has_debug = any(n.startswith('.debug') for n in section_names)
    is_stripped = not has_symtab

    lines.append(f"Symbol table (.symtab): {'Present' if has_symtab else 'Absent'}")
    lines.append(f"Debug sections:         {'Present' if has_debug else 'Absent'}")
    if is_stripped:
        lines.append("[!] Binary is STRIPPED — static symbol table removed; "
                     "reverse engineering is significantly harder")
    else:
        lines.append("Binary is NOT stripped — symbol names are available")

    # Dynamic vs static linking
    has_dynamic = any(str(seg.type).endswith('PT_DYNAMIC') for seg in binary.segments)
    has_interp = any(str(seg.type).endswith('PT_INTERP') for seg in binary.segments)
    lines.append("")

    if has_dynamic or has_interp:
        lines.append("Linking: DYNAMIC (shared libraries required at runtime)")
        # Extract interpreter path
        for seg in binary.segments:
            if str(seg.type).endswith('PT_INTERP'):
                try:
                    interp = bytes(seg.content).rstrip(b'\x00').decode('utf-8', errors='replace')
                    lines.append(f"Interpreter: {interp}")
                except Exception:
                    pass
                break
    else:
        lines.append("Linking: STATIC (no dynamic interpreter — fully self-contained)")
        lines.append("[~] Statically linked binary — may be attempting to avoid dependency on system libs")

    # Dynamic symbol count
    dyn_syms = list(binary.dynamic_symbols)
    lines.append(f"\nDynamic symbols: {len(dyn_syms)}")
    static_syms = [s for s in binary.symbols if s.name and s not in dyn_syms]
    lines.append(f"Static symbols:  {len(static_syms)}")

    # Sections overview
    lines.append(f"\nSections present: {', '.join(sorted(section_names)) if section_names else '(none)'}")

    return '\n'.join(lines)
