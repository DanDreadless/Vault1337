import os
import yara

def run_yara(file_path):
    rules_path = 'vault/yara-rules/'

    # Create an empty dictionary to store rules
    rules_dict = {}

    # Loop through all files in the rules_path
    for root, dirs, files in os.walk(rules_path):
        for file in files:
            if file.endswith('.yar'):
                file_path = os.path.join(root, file)
                rules_dict[file] = file_path

    # Compile the rules from the dictionary
    if rules_dict:
        compiled_rules = yara.compile(filepaths=rules_dict)
        matches = compiled_rules.match(file_path)
        return matches
    else:
        return "No YARA rules found in the specified directory."