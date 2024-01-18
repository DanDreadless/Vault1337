import lief

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