import fitz  # PyMuPDF
import PyPDF2
import zlib

def extract_objects_from_pdf(file_path):
    # Extract text using PyMuPDF
    document = fitz.open(file_path)
    full_text = ""
    for page_num in range(len(document)):
        page = document.load_page(page_num)
        full_text += page.get_text() + "\n\n"  # Add new lines between pages for clarity
    
    # Extract streams using PyPDF2
    streams = []
    with open(file_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        num_pages = len(reader.pages)
        for i in range(num_pages):
            page = reader.pages[i]
            page_content = page.get_contents()
            
            if isinstance(page_content, PyPDF2.generic.ArrayObject):
                content = b''.join([c.get_data() for c in page_content])
            else:
                content = page_content.get_data()
            
            # Truncate content for clarity, showing only the first 200 bytes
            raw_data = content[:200]
            decompressed_data = None
            decompression_error = None
            
            # Try to decompress the stream if it is compressed
            try:
                decompressed_content = zlib.decompress(content)
                decompressed_data = decompressed_content[:200]  # First 200 bytes for brevity
            except Exception as e:
                decompression_error = str(e)
            
            streams.append({
                "page_number": i + 1,
                "raw_data": raw_data.decode(errors='replace'),  # Decode bytes to string, replacing errors
                "decompressed_data": decompressed_data.decode(errors='replace') if decompressed_data else None,
                "decompression_error": decompression_error
            })
    
    # Format the output into a single string
    result = []
    result.append("Extracted Text:\n")
    result.append(full_text.strip())
    
    result.append("\nStream Data:\n")
    for stream in streams:
        result.append(f"\nPage Number: {stream['page_number']}")
        result.append(f"Raw Data (Preview): {stream['raw_data'][:100]}")  # Preview first 100 characters
        if stream.get("decompressed_data"):
            result.append(f"Decompressed Data (Preview): {stream['decompressed_data'][:100]}")  # Preview first 100 characters
        if stream.get("decompression_error"):
            result.append(f"Decompression Error: {stream['decompression_error']}")
    
    return "\n".join(result)
