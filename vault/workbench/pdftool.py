"""
PDF forensic analysis tool.

Uses pypdf (BSD-3-Clause), pdfminer.six (MIT), and pypdfium2 (Apache-2.0)
for static analysis and page rendering. PyMuPDF (AGPL-3.0) has been removed
to satisfy commercial licensing requirements — see docs/licensing.md.

All rendering is pure pixel rasterisation: no JavaScript execution, no active
content, no network access.
"""

import base64
import io
import logging
import os
import re
import textwrap
from datetime import datetime, timedelta

import pypdfium2 as pdfium
from pdfminer.high_level import extract_text
from PIL import Image
from pypdf import PdfReader
from tabulate import tabulate

logger = logging.getLogger(__name__)

MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB

# Known-malicious PDF keywords for raw byte scanning.
_SUSPICIOUS_KEYWORDS = [
    (b"/JavaScript",  "JavaScript execution"),
    (b"/JS",          "JavaScript shorthand"),
    (b"/Launch",      "Launch action (execute files/commands)"),
    (b"/OpenAction",  "OpenAction (executes on PDF open)"),
    (b"/AA",          "Additional Actions trigger"),
    (b"/EmbeddedFile","Embedded file"),
    (b"/RichMedia",   "RichMedia annotation (Flash/media)"),
    (b"/AcroForm",    "Interactive form (AcroForm)"),
    (b"/XFA",         "XFA form (XML script-capable)"),
    (b"/JBIG2Decode", "JBIG2Decode filter (used in exploits)"),
    (b"/ObjStm",      "Object stream (can hide objects from scanners)"),
    (b"/GoToR",       "Remote GoTo action (links external PDF)"),
    (b"/GoToE",       "Embedded GoTo action"),
    (b"/SubmitForm",  "SubmitForm action (exfiltrates form data)"),
    (b"/ImportData",  "ImportData action"),
    (b"/Encrypt",     "Encryption present"),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _try_decrypt(reader: PdfReader) -> None:
    """Attempt to decrypt an encrypted PDF with an empty password.

    Logs a warning if the PDF remains encrypted after the attempt.
    """
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:
            pass
        if reader.is_encrypted:
            logger.warning("PDF is encrypted and could not be decrypted with empty password")


def _iter_name_tree(node):
    """Recursively iterate a PDF name tree, yielding (name, value) pairs.

    Handles both leaf nodes (containing a /Names array) and intermediate
    nodes (containing a /Kids array of child nodes).
    """
    if hasattr(node, "get_object"):
        node = node.get_object()
    if "/Names" in node:
        names_arr = node["/Names"]
        for i in range(0, len(names_arr) - 1, 2):
            yield names_arr[i], names_arr[i + 1]
    if "/Kids" in node:
        for kid in node["/Kids"]:
            yield from _iter_name_tree(kid)


def _get_js_text(obj) -> str | None:
    """Extract the JavaScript text string from a PDF action or JS dict object.

    Returns None if no /JS key is present or the value is empty.
    """
    if hasattr(obj, "get_object"):
        obj = obj.get_object()
    js = obj.get("/JS")
    if js is None:
        return None
    if hasattr(js, "get_object"):
        js = js.get_object()
    # Stream object (JS stored as compressed/raw stream)
    if hasattr(js, "get_data"):
        return js.get_data().decode("latin-1", errors="replace")
    text = str(js)
    return text if text else None


def _format_pdf_date(value) -> str:
    """Format a PDF date value as a human-readable string.

    Accepts a datetime object (from pypdf's parsed properties) or a raw PDF
    date string in D:YYYYMMDDHHmmSSOHH'mm format.
    """
    if value is None:
        return "N/A"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return convert_pdf_date(str(value))


def _get_catalog(reader: PdfReader):
    """Return the PDF document catalog dict, dereferenced."""
    root = reader.trailer.get("/Root")
    if root is None:
        return {}
    if hasattr(root, "get_object"):
        root = root.get_object()
    return root


def _get_names_subtree(catalog, key: str):
    """Return a specific subtree from /Root/Names (e.g. /JavaScript, /EmbeddedFiles).

    Returns None if not present.
    """
    names_ref = catalog.get("/Names")
    if names_ref is None:
        return None
    if hasattr(names_ref, "get_object"):
        names_ref = names_ref.get_object()
    subtree = names_ref.get(key)
    if subtree is None:
        return None
    if hasattr(subtree, "get_object"):
        subtree = subtree.get_object()
    return subtree


# ---------------------------------------------------------------------------
# Date conversion (preserves existing format used by metadata tab)
# ---------------------------------------------------------------------------

def convert_pdf_date(pdf_date_str: str) -> str:
    """Convert a raw PDF date string (D:YYYYMMDDHHmmSSOHH'mm) to ISO format."""
    if pdf_date_str and pdf_date_str.startswith("D:"):
        date_str = pdf_date_str[2:]
        timezone_part = date_str[14:]
        timezone_offset = re.sub(r"[']+", "", timezone_part)
        try:
            pdf_datetime = datetime.strptime(date_str[:14], "%Y%m%d%H%M%S")
            if timezone_offset:
                sign = timezone_offset[0]
                hours_offset = int(timezone_offset[1:3])
                minutes_offset = int(timezone_offset[3:5])
                timezone_delta = timedelta(hours=hours_offset, minutes=minutes_offset)
                if sign == "-":
                    pdf_datetime = pdf_datetime - timezone_delta
                else:
                    pdf_datetime = pdf_datetime + timezone_delta
            return pdf_datetime.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return f"Invalid Date Format: {pdf_date_str}"
    return "N/A"


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

def extract_urls_from_text(text: str) -> list[str]:
    url_pattern = re.compile(r"(https?://[^\s]+)")
    return url_pattern.findall(text)


def extract_urls_from_stream(file_path: str) -> list[str]:
    """Stream-scan raw PDF bytes for URLs (catches obfuscated/embedded URIs)."""
    file_size = os.path.getsize(file_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        return [f"[!] File too large ({mb} MB) to stream-scan for URLs."]
    urls: list[str] = []
    with open(file_path, "rb") as f:
        buffer = b""
        while chunk := f.read(4096):
            buffer += chunk
            matches = re.findall(r"(https?://[^\s]+)", buffer.decode("utf-8", errors="ignore"))
            urls.extend(matches)
            buffer = buffer[-100:]
    return list(set(urls))


def extract_urls_from_pdf(pdf_path: str) -> list[str]:
    """Extract URIs from PDF link annotations (/Annots with /Subtype /Link)."""
    urls: list[str] = []
    try:
        reader = PdfReader(pdf_path, strict=False)
        _try_decrypt(reader)
        for page in reader.pages:
            annots = page.get("/Annots")
            if not annots:
                continue
            for annot_ref in annots:
                try:
                    annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                    if annot.get("/Subtype") != "/Link":
                        continue
                    action = annot.get("/A")
                    if action is None:
                        continue
                    if hasattr(action, "get_object"):
                        action = action.get_object()
                    if action.get("/S") == "/URI":
                        uri = action.get("/URI")
                        if uri:
                            urls.append(str(uri))
                except Exception:
                    pass
    except Exception as e:
        logger.error("Error extracting URLs from PDF: %s", e)
    return list(set(urls))


def wrap_text(text: str, width: int = 150) -> str:
    return "\n".join(textwrap.wrap(text, width))


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def get_pdf_metadata(pdf_path: str) -> str:
    """Extract document information and structural metadata."""
    pdf_info: dict[str, str] = {}
    try:
        reader = PdfReader(pdf_path, strict=False)
        _try_decrypt(reader)
        meta = reader.metadata or {}

        # PDF version from file header (e.g. b'%PDF-1.7')
        header = reader.pdf_header
        fmt = header.decode("latin-1", errors="replace") if isinstance(header, bytes) else str(header)
        fmt = fmt.lstrip("%")  # strip leading '%' → "PDF-1.7"

        pdf_info = {
            "Format":            fmt,
            "Title":             str(meta.get("/Title", "N/A") or "N/A"),
            "Author":            str(meta.get("/Author", "N/A") or "N/A"),
            "Subject":           str(meta.get("/Subject", "N/A") or "N/A"),
            "Keywords":          str(meta.get("/Keywords", "N/A") or "N/A"),
            "Creator":           str(meta.get("/Creator", "N/A") or "N/A"),
            "Producer":          str(meta.get("/Producer", "N/A") or "N/A"),
            "Creation Date":     _format_pdf_date(
                                     meta.creation_date if hasattr(meta, "creation_date")
                                     else meta.get("/CreationDate")),
            "Modification Date": _format_pdf_date(
                                     meta.modification_date if hasattr(meta, "modification_date")
                                     else meta.get("/ModDate")),
            "Trapped":           str(meta.get("/Trapped", "N/A") or "N/A"),
            "Page Count":        str(len(reader.pages)),
            "Encrypted":         "Yes" if reader.is_encrypted else "No",
            "XMP Metadata":      "Present" if reader.xmp_metadata else "Not present",
        }
    except Exception as e:
        logger.exception(e)
        pdf_info["Error"] = f"Error getting PDF metadata: {e}"
    return tabulate(pdf_info.items(), headers=["Field", "Value"], tablefmt="grid")


# ---------------------------------------------------------------------------
# Text content
# ---------------------------------------------------------------------------

def extract_pdf_content(pdf_path: str) -> str:
    file_size = os.path.getsize(pdf_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        return f"Error: File too large ({mb} MB). Maximum is 10 MB."
    text = extract_text(pdf_path).strip()
    if not text:
        return (
            "No text content found. "
            "The PDF may be image-only, encrypted, use non-standard encoding, "
            "or contain only graphical/form content."
        )
    return text


# ---------------------------------------------------------------------------
# Image extraction
# ---------------------------------------------------------------------------

def extract_images_from_pdf(pdf_path: str, height: int = 200) -> str:
    """Extract embedded images from all pages, returned as base64 PNG thumbnails.

    Attempts pypdf's built-in PIL conversion first; falls back to opening the
    raw image bytes directly with Pillow. This handles JPEG, JPEG2000, and
    colour spaces that pypdf's conversion path may reject.
    """
    rows: list[str] = []
    try:
        reader = PdfReader(pdf_path, strict=False)
        _try_decrypt(reader)
        for page in reader.pages:
            for image_obj in page.images:
                try:
                    # Primary path: pypdf constructs a PIL Image
                    pil_image = None
                    try:
                        pil_image = image_obj.image
                    except Exception:
                        pass

                    # Fallback: open the raw stream bytes directly
                    if pil_image is None:
                        pil_image = Image.open(io.BytesIO(image_obj.data))

                    # Normalise colour mode to something PNG can encode
                    if pil_image.mode not in ("RGB", "RGBA", "L"):
                        pil_image = pil_image.convert("RGB")

                    w = int(pil_image.width * (height / float(pil_image.height)))
                    pil_image = pil_image.resize((w, height), Image.LANCZOS)
                    buf = io.BytesIO()
                    pil_image.save(buf, format="PNG")
                    b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
                    rows.append(
                        f'<tr><td><img src="data:image/png;base64,{b64}" '
                        f'style="display:block;" /></td></tr>'
                    )
                except Exception as e:
                    logger.debug("Skipping image object %s: %s", getattr(image_obj, "name", "?"), e)
    except Exception as e:
        logger.exception(e)
        return f"Error extracting images: {e}"

    if not rows:
        return "No embedded images found in this PDF."
    return '<table class="image-table">' + "".join(rows) + "</table>"


# ---------------------------------------------------------------------------
# JavaScript extraction
# ---------------------------------------------------------------------------

def extract_js_from_pdf(pdf_path: str) -> str:
    """Extract JavaScript from all standard PDF locations.

    Covers:
    1. /Root/Names/JavaScript name tree (document-level scripts)
    2. /Root/OpenAction of type /JavaScript
    3. /Root/AA document Additional Actions
    4. Per-page /AA Additional Actions
    5. Per-page annotation /A actions of type /JavaScript
    6. AcroForm field /A actions of type /JavaScript
    """
    js_texts: list[str] = []
    try:
        reader = PdfReader(pdf_path, strict=False)
        _try_decrypt(reader)
        catalog = _get_catalog(reader)

        # 1. Document-level JavaScript name tree
        js_tree = _get_names_subtree(catalog, "/JavaScript")
        if js_tree is not None:
            for name, ref in _iter_name_tree(js_tree):
                try:
                    js_obj = ref.get_object() if hasattr(ref, "get_object") else ref
                    text = _get_js_text(js_obj)
                    if text:
                        js_texts.append(f"[NameTree: {name}]\n{text}")
                except Exception:
                    pass

        # 2. /OpenAction
        open_action = catalog.get("/OpenAction")
        if open_action is not None:
            if hasattr(open_action, "get_object"):
                open_action = open_action.get_object()
            if open_action.get("/S") == "/JavaScript":
                text = _get_js_text(open_action)
                if text:
                    js_texts.append(f"[OpenAction]\n{text}")

        # 3. Document-level /AA (Additional Actions)
        doc_aa = catalog.get("/AA")
        if doc_aa is not None:
            if hasattr(doc_aa, "get_object"):
                doc_aa = doc_aa.get_object()
            for event_key in ("/WC", "/WS", "/DS", "/WP", "/DP"):
                action = doc_aa.get(event_key)
                if action is None:
                    continue
                if hasattr(action, "get_object"):
                    action = action.get_object()
                if action.get("/S") == "/JavaScript":
                    text = _get_js_text(action)
                    if text:
                        js_texts.append(f"[DocAA {event_key}]\n{text}")

        # 4. Per-page /AA and annotation actions
        for page_num, page in enumerate(reader.pages, 1):
            page_aa = page.get("/AA")
            if page_aa is not None:
                if hasattr(page_aa, "get_object"):
                    page_aa = page_aa.get_object()
                for event_key in ("/O", "/C"):
                    action = page_aa.get(event_key)
                    if action is None:
                        continue
                    if hasattr(action, "get_object"):
                        action = action.get_object()
                    if action.get("/S") == "/JavaScript":
                        text = _get_js_text(action)
                        if text:
                            js_texts.append(f"[Page {page_num} /AA {event_key}]\n{text}")

            # 5. Annotation-level actions
            annots = page.get("/Annots")
            if annots:
                for annot_ref in annots:
                    try:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        action = annot.get("/A")
                        if action is None:
                            continue
                        if hasattr(action, "get_object"):
                            action = action.get_object()
                        if action.get("/S") == "/JavaScript":
                            text = _get_js_text(action)
                            if text:
                                js_texts.append(f"[Page {page_num} Annotation]\n{text}")
                    except Exception:
                        pass

        # 6. AcroForm field actions
        acroform = catalog.get("/AcroForm")
        if acroform is not None:
            if hasattr(acroform, "get_object"):
                acroform = acroform.get_object()
            fields = acroform.get("/Fields")
            if fields:
                for field_ref in fields:
                    try:
                        field = field_ref.get_object() if hasattr(field_ref, "get_object") else field_ref
                        action = field.get("/A")
                        if action is None:
                            continue
                        if hasattr(action, "get_object"):
                            action = action.get_object()
                        if action.get("/S") == "/JavaScript":
                            text = _get_js_text(action)
                            field_name = field.get("/T", "unnamed")
                            if text:
                                js_texts.append(f"[AcroForm Field: {field_name}]\n{text}")
                    except Exception:
                        pass

    except Exception as e:
        logger.exception(e)
        return f"Error extracting JavaScript: {e}"

    if not js_texts:
        return "No JavaScript found in PDF."
    return "\n\n".join(js_texts)


# ---------------------------------------------------------------------------
# Embedded files
# ---------------------------------------------------------------------------

def extract_embedded_files_from_pdf(pdf_path: str) -> str:
    """List files embedded in the PDF via the /EmbeddedFiles name tree."""
    try:
        reader = PdfReader(pdf_path, strict=False)
        _try_decrypt(reader)
        catalog = _get_catalog(reader)

        ef_tree = _get_names_subtree(catalog, "/EmbeddedFiles")
        if ef_tree is None:
            return "No embedded files found."

        entries = list(_iter_name_tree(ef_tree))
        if not entries:
            return "No embedded files found."

        lines = [f"Embedded files ({len(entries)}):"]
        for idx, (name, ref) in enumerate(entries, 1):
            try:
                fs_obj = ref.get_object() if hasattr(ref, "get_object") else ref
                # /EF dict contains the actual file stream references
                ef_dict = fs_obj.get("/EF", {})
                if hasattr(ef_dict, "get_object"):
                    ef_dict = ef_dict.get_object()
                stream_ref = ef_dict.get("/F") or ef_dict.get("/UF")
                size = "unknown"
                usize = "unknown"
                date_str = ""
                if stream_ref is not None:
                    stream_obj = stream_ref.get_object() if hasattr(stream_ref, "get_object") else stream_ref
                    params = stream_obj.get("/Params", {})
                    if hasattr(params, "get_object"):
                        params = params.get_object()
                    if params:
                        size = params.get("/Size", "unknown")
                        usize = params.get("/Size", "unknown")  # compressed = /Length, uncompressed = /Size
                        raw_date = params.get("/CreationDate") or params.get("/ModDate")
                        date_str = _format_pdf_date(raw_date) if raw_date else ""
                    # Actual compressed size is the stream /Length
                    compressed = stream_obj.get("/Length", "unknown")
                    size = compressed
                lines.append(
                    f"  [{idx}] Name: {name}, Compressed: {size} bytes, "
                    f"Uncompressed: {usize} bytes, Date: {date_str or 'N/A'}"
                )
            except Exception as e:
                lines.append(f"  [{idx}] Error reading info: {e}")
        return "\n".join(lines)
    except Exception as e:
        logger.exception(e)
        return f"Error extracting embedded files: {e}"


# ---------------------------------------------------------------------------
# Page rendering
# ---------------------------------------------------------------------------

def render_pdf_pages(pdf_path: str, zoom: float = 1.5, max_pages: int = 15) -> str:
    """Rasterise each PDF page to PNG using pypdfium2 (Apache-2.0).

    Safety guarantee: pypdfium2 wraps Chrome's PDFium library compiled without
    its JavaScript embedder. Page rendering is pure raster pixel output —
    no JavaScript is executed, no active content is triggered, no network
    requests are made, and no embedded files are launched. Each page becomes
    a static PNG image identical to what you would see by printing to PDF
    from a trusted viewer.
    """
    file_size = os.path.getsize(pdf_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        return f"[!] File too large ({mb} MB) to render. Maximum is 10 MB."
    try:
        doc = pdfium.PdfDocument(pdf_path)
        try:
            page_count = len(doc)
            limit = min(page_count, max_pages)
            parts = ['<div style="display:flex;flex-direction:column;gap:12px;">']
            for i in range(limit):
                page = doc[i]
                bitmap = page.render(scale=zoom)
                pil_img = bitmap.to_pil()
                buf = io.BytesIO()
                pil_img.save(buf, format="PNG")
                b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
                parts.append(
                    f"<div>"
                    f'<div style="font-size:11px;color:#888;margin-bottom:4px;">'
                    f"Page {i + 1} of {page_count}</div>"
                    f'<img src="data:image/png;base64,{b64}" '
                    f'style="max-width:100%;border:1px solid #333;display:block;" />'
                    f"</div>"
                )
            if page_count > max_pages:
                parts.append(
                    f'<p style="color:#888;font-size:12px;">'
                    f"[!] {page_count - max_pages} additional page(s) not shown "
                    f"(limit: {max_pages}).</p>"
                )
            parts.append("</div>")
        finally:
            doc.close()
        return "".join(parts)
    except Exception as e:
        logger.exception(e)
        return f"Error rendering PDF pages: {e}"


# ---------------------------------------------------------------------------
# NEW: Suspicious indicator scan
# ---------------------------------------------------------------------------

def extract_suspicious_indicators(pdf_path: str) -> str:
    """Two-pass forensic scan for known-malicious PDF patterns.

    Pass 1 — Raw byte scan: counts occurrences of 16 suspicious keywords.
    Pass 2 — Structural analysis: checks document catalog, actions, forms,
    annotations, and name trees for exploitation indicators.
    """
    sections: list[str] = []

    # --- Pass 1: raw byte keyword scan ---
    file_size = os.path.getsize(pdf_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        sections.append(
            f"[!] File too large ({mb} MB) to stream-scan. "
            "Raw keyword pass skipped."
        )
    else:
        try:
            with open(pdf_path, "rb") as f:
                raw = f.read()
            hits = [
                (kw.decode("ascii"), desc, raw.count(kw))
                for kw, desc in _SUSPICIOUS_KEYWORDS
                if raw.count(kw) > 0
            ]
            if hits:
                sections.append("=== Raw keyword hits ===")
                sections.append(
                    tabulate(hits, headers=["Keyword", "Description", "Count"], tablefmt="grid")
                )
            else:
                sections.append("Raw keyword scan: no suspicious keywords found.")
        except Exception as e:
            logger.exception(e)
            sections.append(f"Raw keyword scan error: {e}")

    # --- Pass 2: structural analysis ---
    try:
        reader = PdfReader(pdf_path, strict=False)
        flags: list[str] = []

        # Encryption
        if reader.is_encrypted:
            flags.append("[!] PDF is ENCRYPTED")
            try:
                result = reader.decrypt("")
                if result:
                    flags.append("    -> Opened with empty password (auto-open risk)")
            except Exception:
                flags.append("    -> Could not decrypt with empty password")

        catalog = _get_catalog(reader)

        # /OpenAction
        open_action = catalog.get("/OpenAction")
        if open_action is not None:
            if hasattr(open_action, "get_object"):
                open_action = open_action.get_object()
            action_type = open_action.get("/S", "unknown")
            flags.append(f"[!] /OpenAction present — type: {action_type}")

        # Document Additional Actions
        doc_aa = catalog.get("/AA")
        if doc_aa is not None:
            if hasattr(doc_aa, "get_object"):
                doc_aa = doc_aa.get_object()
            aa_keys = list(doc_aa.keys())
            flags.append(f"[!] Document /AA (Additional Actions) present: {aa_keys}")

        # AcroForm
        acroform = catalog.get("/AcroForm")
        if acroform is not None:
            flags.append("[!] /AcroForm (interactive form) present")
            if hasattr(acroform, "get_object"):
                acroform = acroform.get_object()
            if "/XFA" in acroform:
                flags.append("    -> /XFA form found (script-capable XML form)")

        # JavaScript name tree
        js_tree = _get_names_subtree(catalog, "/JavaScript")
        if js_tree is not None:
            js_entries = list(_iter_name_tree(js_tree))
            flags.append(f"[!] /JavaScript name tree: {len(js_entries)} entr{'y' if len(js_entries) == 1 else 'ies'}")

        # Embedded files name tree
        ef_tree = _get_names_subtree(catalog, "/EmbeddedFiles")
        if ef_tree is not None:
            ef_entries = list(_iter_name_tree(ef_tree))
            flags.append(f"[!] /EmbeddedFiles name tree: {len(ef_entries)} entr{'y' if len(ef_entries) == 1 else 'ies'}")

        # Per-page checks
        page_aa_pages: list[int] = []
        launch_count = 0
        js_annot_count = 0
        for page_num, page in enumerate(reader.pages, 1):
            if page.get("/AA"):
                page_aa_pages.append(page_num)
            annots = page.get("/Annots")
            if annots:
                for annot_ref in annots:
                    try:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        action = annot.get("/A")
                        if action is None:
                            continue
                        if hasattr(action, "get_object"):
                            action = action.get_object()
                        s = action.get("/S")
                        if s == "/Launch":
                            launch_count += 1
                        elif s == "/JavaScript":
                            js_annot_count += 1
                    except Exception:
                        pass

        if page_aa_pages:
            flags.append(f"[!] Page /AA (Additional Actions) on pages: {page_aa_pages}")
        if launch_count:
            flags.append(f"[!] /Launch actions in annotations: {launch_count}")
        if js_annot_count:
            flags.append(f"[!] /JavaScript annotation actions: {js_annot_count}")

        if flags:
            sections.append("\n=== Structural indicators ===")
            sections.extend(flags)
        else:
            sections.append("\nStructural analysis: no suspicious indicators found.")

    except Exception as e:
        logger.exception(e)
        sections.append(f"\nStructural analysis error: {e}")

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# NEW: PDF structure overview
# ---------------------------------------------------------------------------

def extract_pdf_structure(pdf_path: str) -> str:
    """High-level structural overview of the PDF for analyst triage.

    Reports: version, page count, encryption, annotation inventory,
    form presence, JavaScript / embedded-file counts, and XMP metadata.
    """
    try:
        reader = PdfReader(pdf_path, strict=False)
        _try_decrypt(reader)
        catalog = _get_catalog(reader)

        # PDF version
        header = reader.pdf_header
        version = (
            header.decode("latin-1", errors="replace").lstrip("%")
            if isinstance(header, bytes) else str(header)
        )

        # Encryption
        encryption = "No"
        if reader.is_encrypted:
            # Check the standard encryption dict for revision/algorithm
            encrypt_dict = reader.trailer.get("/Encrypt")
            if encrypt_dict and hasattr(encrypt_dict, "get_object"):
                encrypt_dict = encrypt_dict.get_object()
            if encrypt_dict:
                algo = encrypt_dict.get("/Filter", "unknown")
                rev = encrypt_dict.get("/R", "?")
                encryption = f"Yes ({algo} rev {rev})"
            else:
                encryption = "Yes"

        # Annotation inventory
        annot_types: dict[str, int] = {}
        for page in reader.pages:
            annots = page.get("/Annots")
            if not annots:
                continue
            for annot_ref in annots:
                try:
                    annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                    subtype = str(annot.get("/Subtype", "/Unknown"))
                    annot_types[subtype] = annot_types.get(subtype, 0) + 1
                except Exception:
                    pass
        total_annots = sum(annot_types.values())
        annot_breakdown = ", ".join(
            f"{k}: {v}" for k, v in sorted(annot_types.items(), key=lambda x: -x[1])
        ) if annot_types else "none"

        # JavaScript entries
        js_count = 0
        js_tree = _get_names_subtree(catalog, "/JavaScript")
        if js_tree is not None:
            js_count = len(list(_iter_name_tree(js_tree)))

        # Embedded files
        ef_count = 0
        ef_tree = _get_names_subtree(catalog, "/EmbeddedFiles")
        if ef_tree is not None:
            ef_count = len(list(_iter_name_tree(ef_tree)))

        # Forms
        has_acroform = "/AcroForm" in catalog
        has_xfa = False
        if has_acroform:
            af = catalog["/AcroForm"]
            if hasattr(af, "get_object"):
                af = af.get_object()
            has_xfa = "/XFA" in af

        # XMP
        has_xmp = reader.xmp_metadata is not None

        rows = [
            ("PDF Version",       version),
            ("Page Count",        str(len(reader.pages))),
            ("Encryption",        encryption),
            ("Total Annotations", str(total_annots)),
            ("Annotation Types",  annot_breakdown),
            ("JavaScript Entries",str(js_count)),
            ("Embedded Files",    str(ef_count)),
            ("AcroForm",          "Yes" if has_acroform else "No"),
            ("XFA Form",          "Yes" if has_xfa else "No"),
            ("XMP Metadata",      "Present" if has_xmp else "Not present"),
        ]
        return tabulate(rows, headers=["Field", "Value"], tablefmt="grid")

    except Exception as e:
        logger.exception(e)
        return f"Error analysing PDF structure: {e}"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def extract_forensic_data(pdf_path: str, subtool: str) -> str:
    """Dispatch to the appropriate PDF forensic sub-tool.

    Sub-tools: metadata, render, content, images, urls, js, embedded,
               suspicious, structure
    """
    if subtool == "metadata":
        return get_pdf_metadata(pdf_path)
    if subtool == "render":
        return render_pdf_pages(pdf_path)
    if subtool == "content":
        return extract_pdf_content(pdf_path)
    if subtool == "images":
        return extract_images_from_pdf(pdf_path)
    if subtool == "urls":
        text_urls = extract_urls_from_text(extract_pdf_content(pdf_path))
        stream_urls = extract_urls_from_stream(pdf_path)
        pdf_urls = extract_urls_from_pdf(pdf_path)
        url_data = (
            [(wrap_text(u), "Text") for u in text_urls]
            + [(wrap_text(u), "Stream") for u in stream_urls]
            + [(wrap_text(u), "PDF Links") for u in pdf_urls]
        )
        return tabulate(url_data, headers=["URL", "Source"], tablefmt="grid")
    if subtool == "js":
        return extract_js_from_pdf(pdf_path)
    if subtool == "embedded":
        return extract_embedded_files_from_pdf(pdf_path)
    if subtool == "suspicious":
        return extract_suspicious_indicators(pdf_path)
    if subtool == "structure":
        return extract_pdf_structure(pdf_path)
    return (
        "Invalid subtool. Choose from: "
        "'metadata', 'render', 'content', 'images', 'urls', "
        "'js', 'embedded', 'suspicious', 'structure'."
    )
