import os

def oleobj_parser(filename):
    ole = os.system(f"oleobj {filename}")

if __name__ == "__main__":
    file_path = "C:\\Users\\dread\\Code\\vault1337\\vault\\samples\\bd8c9ae3215333881f06b32aa9f8ffcadd9dab082cd0be8f95d25de59d467084"  # Replace with the path to your OLE file
    result = oleobj_parser(file_path)
    print(result)
