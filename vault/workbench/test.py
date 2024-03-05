import os

def oleobj_parser(filename):
    ole = os.system(f"oleobj {filename}")
<<<<<<< HEAD
    return(ole)

if __name__ == "__main__":
    # file_path = "C:\\Users\\dread\\Code\\vault1337\\vault\\samples\\bd8c9ae3215333881f06b32aa9f8ffcadd9dab082cd0be8f95d25de59d467084"  # Replace with the path to your OLE file
    file_path = "/var/www/Vault1337/vault/samples/bd8c9ae3215333881f06b32aa9f8ffcadd9dab082cd0be8f95d25de59d467084"
    result = oleobj_parser(file_path)
    # print(result)
=======
    return ole
def run(file_path):
    return oleobj_parser(file_path)
if __name__ == "__main__":
    file_path = "C:\\Users\\dread\\Code\\vault1337\\vault\\samples\\bd8c9ae3215333881f06b32aa9f8ffcadd9dab082cd0be8f95d25de59d467084"  # Replace with the path to your OLE file
    run(file_path)
>>>>>>> be6c3f23721e5c1515f2c9588abedf8a287f7e33
