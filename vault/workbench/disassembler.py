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


# ---------------------------------------------------------------------------
# Raw shellcode disassembly
# ---------------------------------------------------------------------------

_SHELLCODE_ARCH_MAP = None  # populated lazily after capstone import check


def _get_arch_map():
    return {
        'x86':   (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
        'x64':   (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
        'arm32': (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
        'arm64': (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }


_MAX_SHELLCODE_BYTES = 1 * 1024 * 1024  # 1 MB; shellcode stagers are tiny


def disassemble_shellcode(file_path: str, arch: str, max_insn: int = 500) -> str:
    """
    Disassemble raw shellcode from file_path as the specified architecture.

    Skips all format parsing — treats the raw file bytes as executable code
    starting at virtual address 0x0.  Useful for:
      - Standalone shellcode blobs
      - Shellcode extracted from PE resources / overlay / documents
      - Payloads extracted from memory dumps

    arch must be one of: x86, x64, arm32, arm64
    """
    if not CAPSTONE_AVAILABLE:
        return "Error: capstone is not installed. Run: pip install capstone"

    arch_map = _get_arch_map()
    if arch not in arch_map:
        supported = ', '.join(sorted(arch_map))
        return f"Unknown architecture '{arch}'. Supported: {supported}"

    cs_arch, cs_mode = arch_map[arch]

    try:
        with open(file_path, 'rb') as fh:
            code = fh.read(_MAX_SHELLCODE_BYTES)
    except Exception as e:
        return f"Error reading file: {e}"

    if not code:
        return "File is empty."

    try:
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = False

        lines = [
            f"Shellcode disassembly ({arch}) — {len(code)} byte(s)",
            f"{'Address':<14} {'Mnemonic':<12} Operands",
            '-' * 60,
        ]

        count = 0
        for insn in md.disasm(code, 0x0):
            lines.append(f"0x{insn.address:08x}    {insn.mnemonic:<12} {insn.op_str}")
            count += 1
            if count >= max_insn:
                lines.append(f"\n... output limited to {max_insn} instructions")
                break

        if count == 0:
            return (
                f"No instructions disassembled as {arch}. "
                "Verify the architecture or check that the file contains raw code bytes."
            )

        lines.append(f"\n[{count} instruction(s)]")
        return '\n'.join(lines)

    except Exception as e:
        logger.exception(e)
        return f"Error during shellcode disassembly: {e}"
