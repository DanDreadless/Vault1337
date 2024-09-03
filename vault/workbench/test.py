import lief
from tabulate import tabulate

binary = lief.parse("edec55f87e535f869119db44e4e7302081f53dbf33a27aaf905430cedc5a78b9")
print(binary.format)  # Print the format of the binary (e.g., PE, ELF)
if binary.format == lief.EXE_FORMATS.PE:
    print("Binary is a PE file")
else:
    print("Binary format not recognized as PE")
if not binary.imports:
    print("No imports found")
else:
    print(f"Found {len(binary.imports)} imported libraries")
print("Imports: ", binary.imports)  # Inspect the raw import table
# Check if there are any imports
if not binary.has_imports:
    print("No imports found")
else:
    print(f"Found {len(binary.imports)} imported libraries")

    result = []
    headers = ["Library", "Function Name", "Address", "Ordinal"]

    for library in binary.imports:
        lib_name = library.name
        for entry in library.entries:
            func_name = entry.name if entry.name else "N/A"
            address = entry.iat_address
            ordinal = entry.ordinal if entry.is_ordinal else "N/A"
            result.append([lib_name, func_name, address, ordinal])

    # Print the imports in a tabulated format
    pe_header = tabulate(result, headers=headers, tablefmt="grid")
    print(pe_header)