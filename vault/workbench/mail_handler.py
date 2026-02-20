import os
import re
from vault.models import File
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from vault.workbench import save_sample
from django.conf import settings

def email_subtool_parser(sub_tool, filename):
    if sub_tool == 'email_headers':
        return extract_email_headers(filename)
    if sub_tool == 'email_body':
        return extract_email_body(filename)
    if sub_tool == 'download_attachments':
        return download_attachments(filename)
    if sub_tool == 'url_extractor':
        return url_extractor(filename)

def url_extractor(file_path):
    if not os.path.isfile(file_path):
        return "Error: File does not exist."

    try:
        with open(file_path, 'rb') as file:
            msg = BytesParser(policy=policy.default).parse(file)

        urls = set()  # Use a set to avoid duplicates

        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()

            if content_type in ['text/plain', 'text/html']:
                charset = part.get_content_charset(failobj='utf-8')
                try:
                    payload = part.get_payload(decode=True).decode(charset, errors='replace')
                except Exception:
                    continue

                # Extract URLs from text
                urls.update(re.findall(r'https?://[^\s"\'<>]+', payload))

                if content_type == 'text/html':
                    soup = BeautifulSoup(payload, 'html.parser')
                    for a_tag in soup.find_all('a', href=True):
                        urls.add(a_tag['href'])

            elif content_type.startswith('image/') and content_disposition != 'inline':
                filename = part.get_filename()
                if filename:
                    cid = part.get('Content-ID', '').strip('<>')
                    if cid:
                        urls.add(f'cid:{cid}')

        if urls:
            return "\n\n".join(sorted(urls))
        else:
            return "No URLs found."

    except Exception as e:
        return f"Error: {str(e)}"

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
    storage_location = settings.SAMPLE_STORAGE_DIR
    if not os.path.isfile(file_path):
        return "Error: File does not exist."

    try:
        with open(file_path, 'rb') as file:
            msg = BytesParser(policy=policy.default).parse(file)
            
            attachments = extract_attachments(msg)

            
            if not attachments:
                return "No attachments found."

            for attachment in attachments:
                try:
                    ext_check = self.sample.name.split('.')
                    if len(ext_check) > 1:
                        filetype = self.sample.name.split('.')[-1]
                        self.tags.append(filetype)
                except:
                    filetype = ''
                filetype = attachment[0].split('.')[-1]
                tags = ['eml_attachment', filetype]
                self = None
                filename, data = attachment
                output_path = os.path.join(storage_location, filename)
                with open(output_path, 'wb') as output_file:
                    output_file.write(data)

                md5, sha1, sha256, sha512, magic_byte, size, mime = save_sample.SaveSample.hash_sample(self, output_path)
                # Check if the file already exists in the database
                if File.objects.filter(sha256=sha256).exists():
                    os.remove(output_path)
                    return 'File already exists'
                # Rename the extracted file to its SHA256 hash to ensure uniqueness
                new_file_name = os.path.join(storage_location, sha256)
                os.rename(output_path, new_file_name)
                
                # Save the file to the database with its original name and SHA256 hash
                vault_item = File(
                    name=filename,
                    size=size,
                    magic=magic_byte,
                    mime=mime,
                    md5=md5,
                    sha1=sha1,
                    sha256=sha256,
                    sha512=sha512,
                )
                vault_item.save()
                # Add tags to the model
                for tag in tags:
                    vault_item.tag.add(tag.strip())
                vault_item.save()
        
        return f"Attachments saved in vault"
    except Exception as e:
        return f"Error: {str(e)}\n{attachment}"
    
def extract_attachments(msg):
    attachments = []
    for part in msg.iter_parts():
        if part.get_filename():
            attachment = (part.get_filename(), part.get_payload(decode=True))
            attachments.append(attachment)
    return attachments