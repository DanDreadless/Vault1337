import re
import codecs

def extract_objects_from_pdf(file_path):
    try:
        with open(file_path, 'rb') as file:
            pdf_content = file.read().decode('latin-1')

        objects = []
        start_object_pattern = re.compile(r'(\d+)\s+(\d+)\s+obj\b')
        end_object_pattern = re.compile(r'endobj\b')

        object_starts = [match.start() for match in start_object_pattern.finditer(pdf_content)]
        object_ends = [match.end() for match in end_object_pattern.finditer(pdf_content)]

        for start, end in zip(object_starts, object_ends):
            object_data = pdf_content[start:end]
            objects.append(object_data)
        formatted_objects = format_objects(objects)
        return formatted_objects
    except Exception as e:
        return f"Error: {str(e)}"

def format_objects(objects):
    formatted_objects = []
    for obj in objects:
        obj_lines = obj.strip().split('\n')
        obj_id_match = re.search(r'(\d+)\s+(\d+)\s+obj\b', obj_lines[0])
        obj_id = f'obj {obj_id_match.group(1)} {obj_id_match.group(2)}'
        formatted_object = [obj_id]
        for line in obj_lines[1:]:
            # Try decoding hex to UTF-16BE
            try:
                decoded_line = codecs.decode(line.strip().encode('latin-1'), 'hex').decode('utf-16be')
                formatted_object.append(decoded_line)
            except Exception:
                formatted_object.append(line.strip())
        formatted_objects.append('\n'.join(formatted_object))
    return formatted_objects