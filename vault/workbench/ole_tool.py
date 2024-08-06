import os
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
import oletools.oleid
import oletools.olemeta
import oletools.rtfobj as rtfobj
import oletools.oleobj as oleobj


def oletools_subtool_parser(sub_tool, filename):
    if sub_tool == 'olevba':
        return olevba_parser(filename)
    if sub_tool == 'oleid':
        return oleid_parser(filename)
    if sub_tool == 'olemeta':
        return olemeta_parser(filename)
    if sub_tool == 'oleobj':
        return oleobj_parser(filename)
    if sub_tool == 'rtfobj':
        return rtfobj_parser(filename)

def olevba_parser(filename):
    try:
        vbaparser = VBA_Parser(filename)
        macro_data = ""  # Initialize macro_data
        if vbaparser.detect_vba_macros():
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                macro_data += f"Filename    : {filename}\n"
                macro_data += f"OLE stream  : {stream_path}\n"
                macro_data += f"VBA filename: {vba_filename}\n"
                macro_data += f"-------------------- VBA CODE --------------------"
                macro_data += f"\n{vba_code}"
                macro_data += f"\n--------------------------------------------------\n\n"

            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_suspicious():
                macro_data += f"Filename    : {filename}\n"
                macro_data += f"OLE stream  : {stream_path}\n"
                macro_data += f"VBA filename: {vba_filename}\n"
                macro_data += f"-------------------- VBA CODE --------------------"
                macro_data += f"\n{vba_code}"
                macro_data += f"\n--------------------------------------------------\n\n"

        else:
            return f"No VBA Macros found"

        return macro_data
    except Exception as e:
        return f"Error: {str(e)}"
    
def oleid_parser(filename):
    try:
        oid = oletools.oleid.OleID(filename)
        indicators = oid.check()
        oidout = []
        for i in indicators:
            oidout += i.id, i.name, i.type, i.value, i.description
        
        output = ""
        for i in range(0, len(oidout), 5):
            indicator = oidout[i+1]
            value = oidout[i+3]
            description = oidout[i+4]

            output += f"{indicator}: {value} | Description: {description}\n"

        return output
    except Exception as e:  
        return f"Error: {str(e)}"
    
def olemeta_parser(filename):
    try:
        ole = oletools.olemeta.olefile.OleFileIO(filename)
        return ole
    except Exception as e:
        return f"Error: {str(e)}"
    
def oleobj_parser(filename):
    try:
        # THIS IS A BAD IMPLEMENTATION
        ole = os.system(f"oleobj {filename} > oleobj_output.txt")
        with open("oleobj_output.txt", "r") as file:
            ole = file.read()
        os.remove("oleobj_output.txt")
        return ole
    except Exception as e:
        return f"Error: {str(e)}"


def rtfobj_parser(filename):
    try:
        # THIS IS A BAD IMPLEMENTATION
        ole = os.system(f"rtfobj {filename} > rtfobj_output.txt")
        with open("rtfobj_output.txt", "r") as file:
            ole = file.read()
        os.remove("rtfobj_output.txt")
        return ole
    except Exception as e:
        return f"Error: {str(e)}"