import logging

logger = logging.getLogger(__name__)

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning("capstone not installed; disassembler tool unavailable")

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


def disassemble(file_path, max_insn=200):
    """Disassemble the first executable section of a PE or ELF binary."""
    if not CAPSTONE_AVAILABLE:
        return "Error: capstone is not installed. Run: pip install capstone"
    if not LIEF_AVAILABLE:
        return "Error: lief is not installed."

    try:
        binary = lief.parse(file_path)
    except Exception as e:
        return f"Error parsing binary: {str(e)}"

    if binary is None:
        return "Error: unable to parse binary (unsupported format)."

    arch = capstone.CS_ARCH_X86
    mode = capstone.CS_MODE_32
    code = None
    base_addr = 0

    if isinstance(binary, lief.PE.Binary):
        if binary.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            mode = capstone.CS_MODE_64
        for section in binary.sections:
            # Use integer bitmask for MEM_EXECUTE (0x20000000); characteristics_lists
            # was renamed/removed in LIEF 0.14+
            if section.characteristics & 0x20000000:
                code = bytes(section.content)
                base_addr = section.virtual_address + binary.optional_header.imagebase
                break

    elif isinstance(binary, lief.ELF.Binary):
        arch_elf = binary.header.machine_type
        if arch_elf == lief.ELF.ARCH.x86_64:
            mode = capstone.CS_MODE_64
        elif arch_elf == lief.ELF.ARCH.i386:
            mode = capstone.CS_MODE_32
        else:
            return f"Unsupported ELF architecture: {arch_elf}"
        for section in binary.sections:
            # Use SHF_EXECINSTR bitmask (0x4); Section.FLAGS enum moved in LIEF 0.14+
            if section.flags & 0x4:
                code = bytes(section.content)
                base_addr = section.virtual_address
                break

    else:
        return "Unsupported binary format. Only PE and ELF are supported."

    if code is None:
        return "No executable section found."
    if not code:
        return "Executable section is empty."

    try:
        md = capstone.Cs(arch, mode)
        md.detail = False

        lines = [f"{'Address':<14} {'Mnemonic':<12} Operands"]
        lines.append('-' * 60)

        count = 0
        for insn in md.disasm(code, base_addr):
            lines.append(f"0x{insn.address:08x}    {insn.mnemonic:<12} {insn.op_str}")
            count += 1
            if count >= max_insn:
                lines.append(f"... (output limited to {max_insn} instructions)")
                break

        if count == 0:
            return "No instructions disassembled."

        return '\n'.join(lines)
    except Exception as e:
        logger.exception(e)
        return f"Error during disassembly: {str(e)}"
