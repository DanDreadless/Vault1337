import lief
from tabulate import tabulate

def lief_parse_subtool(sub_tool, file_path):
    try:
        binary = lief.parse(file_path)
        if binary:
            if sub_tool == 'dos_header':
                pe_header = binary.dos_header
            elif sub_tool == 'rich_header':
                pe_header = binary.rich_header
            elif sub_tool == 'pe_header':
                pe_header = binary.header
            elif sub_tool == 'entrypoint':
                pe_header = binary.entrypoint
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
                pe_header= tabulate(result, headers=headers, tablefmt="grid")

            else:
                return f"Error: Invalid subtool: {sub_tool}"
            if pe_header:
                return pe_header
            else:
                return f"Failed to retrieve PE header."
        else:
            return f"Error parsing the PE file: {str(file_path)}"
    except Exception as e:
        return f"Error: {str(e)}"