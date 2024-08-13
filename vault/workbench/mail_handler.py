import os
import re
from email import policy
from email.parser import BytesParser
from email import message_from_bytes

def email_subtool_parser(sub_tool, filename):
    if sub_tool == 'email_headers':
        return extract_email_headers(filename)
    if sub_tool == 'email_body':
        return extract_email_body(filename)
    

def extract_email_headers(file_path):
    if not os.path.isfile(file_path):
        return "Error: File does not exist."

    try:
        with open(file_path, 'rb') as file:
            msg = BytesParser(policy=policy.default).parse(file)

        headers = [(header, value) for header, value in msg.items()]
        formatted_headers = format_headers(headers)
        return formatted_headers
    except Exception as e:
        return f"Error: {str(e)}"

def format_headers(headers):
    formatted = ""
    max_len = max(len(header) for header, _ in headers)
    
    for header, value in headers:
        value_lines = value.split('\n')
        formatted += f"{header} :\n{value_lines[0]}\n"
        for line in value_lines[1:]:
            formatted += f"{' ' * (max_len + 3)}{line}\n"  # Align subsequent lines
        formatted += "\n"  # Add a blank line for separation
    
    return formatted

def extract_email_body(file_path):
    if not os.path.isfile(file_path):
        return "Error: File does not exist."

    try:
        with open(file_path, 'rb') as file:
            msg = BytesParser(policy=policy.default).parse(file)
            
            # Extract the content based on preference list
            body = msg.get_body(preferencelist=('plain', 'html')).get_content()
            
            # Strip out multiple consecutive carriage returns
            cleaned_body = strip_multiple_carriage_returns(body)
            
        return cleaned_body
    except Exception as e:
        return f"Error: {str(e)}"

def strip_multiple_carriage_returns(text):
    # Replace multiple consecutive newlines with a single newline
    return re.sub(r'\n\s*\n+', '\n\n', text)

def download_attachments(file_path):
    storage_location =  './vault/samples/'
    if not os.path.isfile(file_path):
        return "Error: File does not exist."

    try:
        with open(file_path, 'rb') as file:
            msg = BytesParser(policy=policy.default).parse(file)
            
            attachments = extract_attachments(msg)
            
            if not attachments:
                return "No attachments found."
            
            for attachment in attachments:
                filename, data = attachment
                output_path = os.path.join(storage_location, filename)
                with open(output_path, 'wb') as output_file:
                    output_file.write(data)
        
        return f"Attachments saved to {storage_location}"
    except Exception as e:
        return f"Error: {str(e)}"
    
def extract_attachments(msg):
    attachments = []
    for part in msg.iter_parts():
        if part.get_filename():
            attachment = (part.get_filename(), part.get_payload(decode=True))
            attachments.append(attachment)
    return attachments