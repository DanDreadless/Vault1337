import hashlib
import logging
import lief
import math
from collections import Counter
from tabulate import tabulate
from datetime import datetime

logger = logging.getLogger(__name__)


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

        else:
            return f"Error: Invalid subtool: {sub_tool}"

        if pe_header:
            return pe_header
        else:
            return f"Failed to retrieve data for sub-tool: {sub_tool}"

    except Exception as e:
        logger.exception(e)
        return f"Error: {str(e)}"
