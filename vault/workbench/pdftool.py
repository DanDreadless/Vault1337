import re
import fitz  # PyMuPDF
from datetime import datetime, timedelta
from pdfminer.high_level import extract_text
from PIL import Image
import io
import base64
from tabulate import tabulate
import textwrap

def extract_urls_from_text(text):
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.findall(text)

def extract_urls_from_stream(file_path):
    urls = []
    with open(file_path, 'rb') as file:
        buffer = b""
        while chunk := file.read(4096):
            buffer += chunk
            matches = re.findall(r'(https?://[^\s]+)', buffer.decode("utf-8", errors='ignore'))
            urls.extend(matches)
            buffer = buffer[-100:]

    # Now check for /URI stream data within the PDF's internal structure
    try:
        doc = fitz.open(file_path)
        for page in doc:
            for annot in page.annots():
                # Check if the annotation is a URI link
                if annot.info.get('uri'):
                    urls.append(annot.info['uri'])
    except Exception as e:
        print(f"Error processing streams: {str(e)}")
    
    return list(set(urls))  # Remove duplicates

def wrap_text(text, width=150):
    return "\n".join(textwrap.wrap(text, width))

def convert_pdf_date(pdf_date_str):
    if pdf_date_str and pdf_date_str.startswith('D:'):
        date_str = pdf_date_str[2:]
        timezone_part = date_str[14:]
        timezone_offset = re.sub(r"[']+", '', timezone_part)
        try:
            pdf_datetime = datetime.strptime(date_str[:14], '%Y%m%d%H%M%S')
            if timezone_offset:
                sign = timezone_offset[0]
                hours_offset = int(timezone_offset[1:3])
                minutes_offset = int(timezone_offset[3:5])
                timezone_delta = timedelta(hours=hours_offset, minutes=minutes_offset)
                pdf_datetime = pdf_datetime - timezone_delta if sign == '-' else pdf_datetime + timezone_delta
            return pdf_datetime.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return f'Invalid Date Format: {pdf_date_str}'
    return 'N/A'

def get_pdf_metadata(pdf_path):
    pdf_info = {}
    try:
        doc = fitz.open(pdf_path)
        metadata = doc.metadata
        pdf_info = {
            'Format': metadata.get('format', 'N/A'),
            'Title': metadata.get('title', 'N/A'),
            'Subject': metadata.get('subject', 'N/A'),
            'Keywords': metadata.get('keywords', 'N/A'),
            'Creator': metadata.get('creator', 'N/A'),
            'Producer': metadata.get('producer', 'N/A'),
            'Creation Date': convert_pdf_date(metadata.get('creationDate', 'N/A')),
            'Modification Date': convert_pdf_date(metadata.get('modDate', 'N/A')),
            'Trapped': metadata.get('trapped', 'N/A'),
            'Encryption': metadata.get('encryption', 'N/A')
        }
    except Exception as e:
        pdf_info['Error'] = f"Error getting PDF metadata: {str(e)}"
    return tabulate(pdf_info.items(), headers=["Field", "Value"], tablefmt="grid")

def extract_pdf_content(pdf_path):
    return extract_text(pdf_path).strip()

def extract_images_from_pdf(pdf_path, height=200):  # Keep height fixed, width dynamic
    images = []
    try:
        doc = fitz.open(pdf_path)
        for page in doc:
            for img in page.get_images(full=True):
                xref = img[0]
                base_image = doc.extract_image(xref)
                image_data = base_image["image"]

                # Open the image with PIL
                image = Image.open(io.BytesIO(image_data))

                # Calculate the dynamic width based on the fixed height
                width = int(image.width * (height / float(image.height)))

                # Resize the image to the new dynamic width and fixed height
                image = image.resize((width, height))

                # Save the resized image to a byte buffer
                img_byte_arr = io.BytesIO()
                image.save(img_byte_arr, format='PNG')
                img_byte_arr = img_byte_arr.getvalue()

                # Convert the resized image to base64
                img_base64 = base64.b64encode(img_byte_arr).decode('utf-8')

                # Append the image tag with resized image
                images.append(f'<img src="data:image/png;base64,{img_base64}" />')
    except Exception as e:
        images = [f"Error extracting images: {str(e)}"]
    return images


def extract_forensic_data(pdf_path, subtool):
    if subtool == 'metadata':
        return get_pdf_metadata(pdf_path)
    elif subtool == 'content':
        return extract_pdf_content(pdf_path)
    elif subtool == 'images':
        return extract_images_from_pdf(pdf_path)
    elif subtool == 'urls':
        text_urls = extract_urls_from_text(extract_pdf_content(pdf_path))
        stream_urls = extract_urls_from_stream(pdf_path)
        url_data = [(wrap_text(url), "Text") for url in text_urls] + [(wrap_text(url), "Stream") for url in stream_urls]
        return tabulate(url_data, headers=["URL", "Source"], tablefmt="grid")
    else:
        return "Invalid subtool. Choose from 'metadata', 'content', 'images', or 'urls'."
