import subprocess
import logging
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
import oletools.oleid
import oletools.olemeta
import oletools.rtfobj as rtfobj
import oletools.oleobj as oleobj

logger = logging.getLogger(__name__)


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
    if sub_tool == 'oledump':
        return oledump_parser(filename)
    return f"Unknown sub-tool: {sub_tool}"

def olevba_parser(filename):
    try:
        vbaparser = VBA_Parser(filename)
        macro_data = ""
        if vbaparser.detect_vba_macros():
            vba_analysis = vbaparser.analyze_macros()
            macro_data += f"------------------ VBA ANALYSIS ------------------\n"
            for kw_type, keyword, description in vba_analysis:
                macro_data += f"Type: {kw_type} | Keyword: {keyword} | Description: {description}\n"

            macro_data += f"\n--------------------------------------------------\n\n"

            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
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
        logger.exception(e)
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
        logger.exception(e)
        return f"Error: {str(e)}"

def olemeta_parser(filename):
    try:
        ole = oletools.olemeta.olefile.OleFileIO(filename)
        meta = ole.get_metadata()

        attrs = [
            ('Title',             meta.title),
            ('Subject',           meta.subject),
            ('Author',            meta.author),
            ('Keywords',          meta.keywords),
            ('Last Author',       meta.last_saved_by),
            ('Company',           meta.company),
            ('Category',          meta.category),
            ('Manager',           meta.manager),
            ('Creation Time',     meta.create_time),
            ('Last Saved Time',   meta.last_saved_time),
        ]

        lines = [f"{'Property':<20} Value"]
        lines.append('-' * 60)
        for name, value in attrs:
            if value is not None:
                if isinstance(value, bytes):
                    value = value.decode('utf-8', errors='replace')
                lines.append(f"{name:<20} {value}")

        return '\n'.join(lines)
    except Exception as e:
        logger.exception(e)
        return f"Error: {str(e)}"

def oleobj_parser(filename):
    try:
        result = subprocess.run(
            ['oleobj', '-s', 'all', filename],
            capture_output=True, text=True, check=False, timeout=30
        )
        output = result.stdout + result.stderr
        return output if output.strip() else "No OLE objects found or no output produced."
    except FileNotFoundError:
        return "Error: oleobj not found. Ensure oletools is installed."
    except subprocess.TimeoutExpired:
        return "Error: oleobj timed out after 30 seconds."
    except Exception as e:
        logger.exception(e)
        return f"Error: {str(e)}"


def rtfobj_parser(filename):
    try:
        result = subprocess.run(
            ['rtfobj', filename],
            capture_output=True, text=True, check=False, timeout=30
        )
        output = result.stdout + result.stderr
        return output if output.strip() else "No RTF objects found or no output produced."
    except FileNotFoundError:
        return "Error: rtfobj not found. Ensure oletools is installed."
    except subprocess.TimeoutExpired:
        return "Error: rtfobj timed out after 30 seconds."
    except Exception as e:
        logger.exception(e)
        return f"Error: {str(e)}"


def oledump_parser(filename):
    try:
        result = subprocess.run(
            ['oledump', filename],
            capture_output=True, text=True, check=False, timeout=30
        )
        output = result.stdout + result.stderr
        return output if output.strip() else "No streams found or no output produced."
    except FileNotFoundError:
        return "Error: oledump not found. Ensure it is installed and on PATH."
    except subprocess.TimeoutExpired:
        return "Error: oledump timed out after 30 seconds."
    except Exception as e:
        logger.exception(e)
        return f"Error: {str(e)}"
