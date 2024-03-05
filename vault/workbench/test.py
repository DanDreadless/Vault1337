import os

def oleobj_parser(filename):
    try:
        # THIS IS A BAD IMPLEMENTATION
        output = ""
        ole = os.system(f"oleobj {filename}")
        for i in ole:
            output += i
        return output
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    file_path = "C:\\Users\\dread\\Code\\vault1337\\vault\\samples\\bd8c9ae3215333881f06b32aa9f8ffcadd9dab082cd0be8f95d25de59d467084"  # Replace with the path to your OLE file
    # file_path = "/var/www/Vault1337/vault/samples/bd8c9ae3215333881f06b32aa9f8ffcadd9dab082cd0be8f95d25de59d467084"
    result = oleobj_parser(file_path)
    # print(result)
