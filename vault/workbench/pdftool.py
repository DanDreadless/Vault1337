import re
import logging
import os
import fitz  # PyMuPDF
from datetime import datetime, timedelta
from pdfminer.high_level import extract_text
from PIL import Image
import io
import base64
from tabulate import tabulate
import textwrap

logger = logging.getLogger(__name__)

MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB


def extract_urls_from_text(text):
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.findall(text)

def extract_urls_from_stream(file_path):
    file_size = os.path.getsize(file_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        return [f"[!] File too large ({mb} MB) to stream-scan for URLs."]
    urls = []
    with open(file_path, 'rb') as file:
        buffer = b""
        while chunk := file.read(4096):
            buffer += chunk
            matches = re.findall(r'(https?://[^\s]+)', buffer.decode("utf-8", errors='ignore'))
            urls.extend(matches)
            buffer = buffer[-100:]
    return list(set(urls))

def extract_urls_from_pdf(pdf_path):
    urls = []
    try:
        doc = fitz.open(pdf_path)
        for page_num in range(len(doc)):
            page = doc.load_page(page_num)
            links = page.get_links()

            for link in links:
                uri = link.get('uri')
                if uri:
                    urls.append(uri)
    except Exception as e:
        logger.error("Error extracting URLs from PDF: %s", str(e))

    return list(set(urls))

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
        logger.exception(e)
        pdf_info['Error'] = f"Error getting PDF metadata: {str(e)}"
    return tabulate(pdf_info.items(), headers=["Field", "Value"], tablefmt="grid")

def extract_pdf_content(pdf_path):
    file_size = os.path.getsize(pdf_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        return f"Error: File too large ({mb} MB). Maximum is 10 MB."
    return extract_text(pdf_path).strip()

def extract_images_from_pdf(pdf_path, height=200):
    images = []
    try:
        doc = fitz.open(pdf_path)
        images.append('<table class="image-table">')
        for page in doc:
            for img in page.get_images(full=True):
                xref = img[0]
                base_image = doc.extract_image(xref)
                image_data = base_image["image"]

                image = Image.open(io.BytesIO(image_data))

                width = int(image.width * (height / float(image.height)))
                image = image.resize((width, height))

                img_byte_arr = io.BytesIO()
                image.save(img_byte_arr, format='PNG')
                img_byte_arr = img_byte_arr.getvalue()

                img_base64 = base64.b64encode(img_byte_arr).decode('utf-8')
                images.append(f'<tr><td><img src="data:image/png;base64,{img_base64}" /></td></tr>')

        images.append('</table>')

    except Exception as e:
        logger.exception(e)
        images = [f"Error extracting images: {str(e)}"]

    return ''.join(images)


def extract_js_from_pdf(pdf_path):
    """Extract JavaScript from a PDF by scanning xref objects for /JS keys."""
    js_texts = []
    try:
        doc = fitz.open(pdf_path)
        xref_count = doc.xref_length()
        for xref in range(1, xref_count):
            try:
                keys = doc.xref_get_keys(xref)
            except Exception:
                continue
            for js_key in ('JS', 'JavaScript'):
                if js_key in keys:
                    try:
                        js_val = doc.xref_get_key(xref, js_key)
                        if js_val and js_val[0] not in ('null', 'none', 'N'):
                            js_texts.append(f"[xref {xref}] {js_val[1]}")
                    except Exception:
                        pass
    except Exception as e:
        logger.exception(e)
        return f"Error extracting JavaScript: {str(e)}"

    if not js_texts:
        return "No JavaScript found in PDF."
    return '\n\n'.join(js_texts)


def extract_embedded_files_from_pdf(pdf_path):
    """List files embedded in the PDF via the EmbeddedFiles name tree."""
    try:
        doc = fitz.open(pdf_path)
        count = doc.embfile_count()
        if count == 0:
            return "No embedded files found."
        lines = [f"Embedded files ({count}):"]
        for i in range(count):
            try:
                info = doc.embfile_info(i)
                name = info.get('filename', f'file_{i}')
                size = info.get('size', info.get('length', 'unknown'))
                usize = info.get('usize', 'unknown')
                date = info.get('creationDate', info.get('date', ''))
                lines.append(f"  [{i+1}] Name: {name}, Size: {size} bytes, Uncompressed: {usize} bytes, Date: {date}")
            except Exception as e:
                lines.append(f"  [{i+1}] Error reading info: {str(e)}")
        return '\n'.join(lines)
    except Exception as e:
        logger.exception(e)
        return f"Error extracting embedded files: {str(e)}"


def render_pdf_pages(pdf_path, zoom=1.5, max_pages=15):
    """Rasterise each PDF page to PNG using PyMuPDF.

    Pure pixel rendering — no JavaScript execution, no active content, no
    network access.  Returns an HTML string of base64-embedded images suitable
    for display in the frontend.
    """
    file_size = os.path.getsize(pdf_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        return f"[!] File too large ({mb} MB) to render. Maximum is 10 MB."
    try:
        doc = fitz.open(pdf_path)
        page_count = len(doc)
        limit = min(page_count, max_pages)
        mat = fitz.Matrix(zoom, zoom)
        parts = ['<div style="display:flex;flex-direction:column;gap:12px;">']
        for i in range(limit):
            page = doc.load_page(i)
            pix = page.get_pixmap(matrix=mat, colorspace=fitz.csRGB)
            img_data = pix.tobytes("png")
            b64 = base64.b64encode(img_data).decode('utf-8')
            parts.append(
                f'<div>'
                f'<div style="font-size:11px;color:#888;margin-bottom:4px;">Page {i + 1} of {page_count}</div>'
                f'<img src="data:image/png;base64,{b64}" style="max-width:100%;border:1px solid #333;display:block;" />'
                f'</div>'
            )
        if page_count > max_pages:
            parts.append(
                f'<p style="color:#888;font-size:12px;">'
                f'[!] {page_count - max_pages} additional page(s) not shown (limit: {max_pages}).'
                f'</p>'
            )
        parts.append('</div>')
        return ''.join(parts)
    except Exception as e:
        logger.exception(e)
        return f"Error rendering PDF pages: {str(e)}"


def extract_forensic_data(pdf_path, subtool):
    if subtool == 'metadata':
        return get_pdf_metadata(pdf_path)
    elif subtool == 'render':
        return render_pdf_pages(pdf_path)
    elif subtool == 'content':
        return extract_pdf_content(pdf_path)
    elif subtool == 'images':
        return extract_images_from_pdf(pdf_path)
    elif subtool == 'urls':
        text_urls = extract_urls_from_text(extract_pdf_content(pdf_path))
        stream_urls = extract_urls_from_stream(pdf_path)
        pdf_urls = extract_urls_from_pdf(pdf_path)
        url_data = [(wrap_text(url), "Text") for url in text_urls] + \
                   [(wrap_text(url), "Stream") for url in stream_urls] + \
                   [(wrap_text(url), "PDF Links") for url in pdf_urls]
        return tabulate(url_data, headers=["URL", "Source"], tablefmt="grid")
    elif subtool == 'js':
        return extract_js_from_pdf(pdf_path)
    elif subtool == 'embedded':
        return extract_embedded_files_from_pdf(pdf_path)
    else:
        return "Invalid subtool. Choose from 'metadata', 'render', 'content', 'images', 'urls', 'js', or 'embedded'."
