import os

def oleobj_parser(filename):
    # Run the command and capture the standard output
    result = os.system(f"oleobj {filename}")
    
    return result

if __name__ == "__main__":
    file_path = "C:\\Users\\dread\\Code\\vault1337\\vault\\samples\\bd8c9ae3215333881f06b32aa9f8ffcadd9dab082cd0be8f95d25de59d467084"  # Replace with the path to your OLE file
    # file_path = "/var/www/Vault1337/vault/samples/bd8c9ae3215333881f06b32aa9f8ffcadd9dab082cd0be8f95d25de59d467084"
    result = oleobj_parser(file_path)
    # print(result)
