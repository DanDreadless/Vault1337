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
        return  ''.join(map(str, formatted_objects))
    except Exception as e:
        return f"Error: {str(e)}"

def format_objects(objects):
    formatted_objects = []
    for obj in objects:
        obj_lines = obj.strip().split('\n')
        obj_id_match = re.search(r'(\d+)\s+(\d+)\s+obj\b', obj_lines[0])
        obj_id = f'obj {obj_id_match.group(1)} {obj_id_match.group(2)}'
        formatted_object = [obj_id]
        has_stream = False  # Flag to track if the object has stream data
        for line in obj_lines[1:]:
            # Check if the line starts with '<<'
            if line.strip().startswith('<<'):
                formatted_object.append(line.strip())
            elif 'stream' in line:
                has_stream = True
                formatted_object.append('Stream data present')  # Indicate presence of stream data
            else:
                # Check if the line contains hexadecimal data between <>
                line_without_hex = re.sub(r'<([0-9A-Fa-f]+)>', lambda x: codecs.decode(x.group(1), 'hex').decode('utf-16be'), line.strip())
                formatted_object.append(line_without_hex)
        if not has_stream:
            formatted_objects.append('\n'.join(formatted_object))  # Join lines with newline character
    return formatted_objects

