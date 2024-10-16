import re
import fitz  # PyMuPDF
from datetime import datetime, timedelta
from pdfminer.high_level import extract_text
from tabulate import tabulate  # Importing tabulate for table formatting

# Helper function to extract URLs from text
def extract_urls(text):
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.findall(text)


def convert_pdf_date(pdf_date_str):
    """Convert PDF date format (D:YYYYMMDDHHMMSS+ZZ'ZZ') to human-readable format."""
    if pdf_date_str and pdf_date_str.startswith('D:'):
        # Remove the 'D:' prefix
        date_str = pdf_date_str[2:]
        
        # Extract the date and timezone part
        date_part = date_str[:14]  # 'YYYYMMDDHHMMSS'
        timezone_part = date_str[14:]  # '+00'00' or similar
        
        # Remove the single quotes from the timezone part and convert it to a proper format
        timezone_offset = re.sub(r"[']+", '', timezone_part)

        try:
            # Parse the date string into a Python datetime object
            pdf_datetime = datetime.strptime(date_part, '%Y%m%d%H%M%S')
            
            # Adjust for the timezone offset (if present)
            if timezone_offset:
                sign = timezone_offset[0]  # '+' or '-'
                hours_offset = int(timezone_offset[1:3])
                minutes_offset = int(timezone_offset[3:5])
                
                # Create a timezone timedelta
                timezone_delta = timedelta(hours=hours_offset, minutes=minutes_offset)
                if sign == '-':
                    pdf_datetime -= timezone_delta
                else:
                    pdf_datetime += timezone_delta
            
            return pdf_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')  # Return in human-readable format
        except ValueError:
            return f'Invalid Date Format: {pdf_date_str}'  # If the date is not in expected format
    return 'N/A'

def get_pdf_info(pdf_path):
    """Retrieve PDF metadata, including human-readable creation and modification dates."""
    pdf_info = {}
    try:
        doc = fitz.open(pdf_path)
        metadata = doc.metadata
        
        # Check if metadata is a dictionary
        if not isinstance(metadata, dict):
            return {"error": "Invalid PDF metadata format"}

        # Extract the basic metadata fields
        pdf_info['format'] = metadata.get('format', 'N/A')
        pdf_info['title'] = metadata.get('title', 'N/A')
        pdf_info['subject'] = metadata.get('subject', 'N/A')
        pdf_info['keywords'] = metadata.get('keywords', 'N/A')
        pdf_info['creator'] = metadata.get('creator', 'N/A')
        pdf_info['producer'] = metadata.get('producer', 'N/A')

        # Convert and format the creation and modification dates
        pdf_info['creationDate'] = convert_pdf_date(metadata.get('creationDate', 'N/A'))
        pdf_info['modificationDate'] = convert_pdf_date(metadata.get('modDate', 'N/A'))

        # Additional fields
        pdf_info['trapped'] = metadata.get('trapped', 'N/A')
        pdf_info['encryption'] = metadata.get('encryption', 'N/A')

    except Exception as e:
        pdf_info['error'] = f"Error getting PDF information: {str(e)}"

    return pdf_info


# Forensic workup of a PDF file
def extract_forensic_data(file_path):
    all_strings = ""
    forensic_report = {
        "pdf_info": {},  # To be filled with PDF metadata
        "urls_found": [],  # List of URLs found in the text
        "raw_pdf_text": "",  # Raw extracted text from PDF
    }

    # Get PDF Info (metadata)
    forensic_report["pdf_info"] = get_pdf_info(file_path)

    # Step 1: Open and read the PDF file in binary mode for string extraction
    with open(file_path, 'rb') as file:
        chunk_size = 4096  # Define the chunk size for reading
        buffer = b""  # Initialize buffer to store content

        while True:
            # Read file in chunks
            chunk = file.read(chunk_size)
            if not chunk:
                break

            buffer += chunk  # Append the chunk to the buffer

            # Attempt to decode the content to UTF-8
            try:
                decoded_content = buffer.decode("utf-8", errors='ignore')
            except UnicodeDecodeError:
                return f"Error: Unable to decode file using 'utf-8' encoding."

            # Extract printable ASCII characters using regex (this helps extract strings)
            matches = re.findall(r'[\x20-\x7E]{4,}', decoded_content)
            all_strings += '\n'.join(matches) + '\n'

            # Retain the last few bytes to handle possible multi-byte characters at chunk boundaries
            buffer = buffer[-10:]

    # Extract any URLs using the extract_urls function and add them to the forensic report
    urls_in_text = extract_urls(all_strings.strip())
    if urls_in_text:
        for url in urls_in_text:
            url = url.replace(')>>>>', '')  # Remove any trailing characters
            forensic_report["urls_found"].append(url)

    # Step 2: Extract PDF text content using pdfminer
    pdf_text = extract_text(file_path)

    # Add the PDF text to the forensic report
    forensic_report["raw_pdf_text"] = pdf_text.strip()

    return forensic_report

# Function to return forensic report with formatting
def get_formatted_forensic_report(report):
    # Table headers for PDF metadata
    headers = ["Field", "Value"]
    
    # PDF Info rows for table
    pdf_info_table = [[key.capitalize(), value] for key, value in report["pdf_info"].items()]
    
    # Generate PDF metadata table using tabulate
    formatted_report = "\n--- PDF Metadata ---\n"
    formatted_report += tabulate(pdf_info_table, headers, tablefmt="grid") + "\n"

    # URLs Found in Text
    formatted_report += "\n--- URLs Found in Text ---\n"
    if report["urls_found"]:
        formatted_report += "\n" + "\n".join([f"  {url}" for url in report["urls_found"]]) + "\n"
    else:
        formatted_report += "  No URLs found.\n"

    # Raw PDF Text (pdfminer)
    formatted_report += "\n--- PDF Content ---\n"
    formatted_report += "\n" + report["raw_pdf_text"] if report["raw_pdf_text"] else "No text found in PDF."

    return formatted_report