import exiftool

# todo: format output so it looks nicer
def get_exif_data(file_path):
    with exiftool.ExifTool() as et:
        metadata = et.execute(file_path)
    return metadata