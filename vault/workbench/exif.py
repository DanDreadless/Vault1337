import logging
import exiftool

logger = logging.getLogger(__name__)


def get_exif_data(file_path):
    try:
        with exiftool.ExifTool() as et:
            metadata = et.execute(file_path)
        if not metadata or not metadata.strip():
            return "No metadata found."
        return metadata
    except Exception as e:
        logger.exception(e)
        return f"Error reading EXIF data: {str(e)}"
