import lief

def get_pe_header(file_path):
    try:
        binary = lief.parse(file_path)
        if binary:
            pe_header = binary.header
            if pe_header:
                returned_header = f"PE Header Information:\n"
                returned_header += f"Architecture: {str(pe_header.machine)}\n"
                returned_header += f"Entry Point: {str(hex(pe_header.entrypoint))}\n"
                returned_header += f"Number of Sections: {str(pe_header.numberof_sections)}\n"
                returned_header += f"Image Base: {str(hex(pe_header.imagebase))}\n"
                # Add more information as needed
                return returned_header
            else:
                return f"Failed to retrieve PE header."
        else:
            return f"Error parsing the PE file: {str(file_path)}"
    except lief.exception as e:
        return f"Error: {str(e)}"