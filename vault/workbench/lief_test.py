import lief
from tabulate import tabulate

def lief_parse_subtool(file_path):
    try:
        binary = lief.parse(file_path)
        if binary:
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

            print(tabulate(result, headers=headers, tablefmt="grid"))
    except Exception as e:
        print(f"Error: {str(e)}")


file_path = "C:\\Users\\dread\\Code\\vault1337\\vault\\samples\\ccde97bb6fc523a56f17625ac7f9f3858247e7df439451423c5e2688793bdf9a"
lief_parse_subtool(file_path)
