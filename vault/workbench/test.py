import py7zr
import os

def test_unzip_sample_7z():
    # Create a test instance of the SaveSample class
    sample = "C:\\Users\\dread\\Downloads\\ScreenConnect.ClientSetup(27).7z"
    storage_location =  './vault/samples/'
    password = "infected"
    try:
        with py7zr.SevenZipFile(sample, mode='r', password=password) as z:
            for extracted_file in z.getnames():
                z.extract(path=storage_location, targets=[extracted_file])
                extracted_file_path = os.path.join(storage_location, extracted_file)
                print(f"Extracted file: {extracted_file_path}")
    except Exception as e:
        print(f"{str(e)}")

test_unzip_sample_7z()