import os
import yara
import json

def run_yara(file_path):
    rules_path = 'vault/yara-rules/'

    # Create an empty list to store matches
    all_matches = []

    # Loop through all files in the rules_path
    for root, dirs, files in os.walk(rules_path):
        for file in files:
            if file.endswith('.yar'):
                rule_path = os.path.join(root, file)

                # Compile each YARA rule individually
                try:
                    rule = yara.compile(filepath=rule_path)
                except yara.SyntaxError as e:
                    print(f"Error compiling {rule_path}: {e}")
                    continue

                # Open the file to scan
                with open(file_path, 'rb') as f:
                    file_data = f.read()

                    # Match against the compiled rule
                    matches = rule.match(data=file_data)

                    # Store matches in a dictionary
                    if matches:
                        rule_matches = {
                            'rule_name': rule_path,
                            'rule_match': str([match.rule for match in matches]),
                            'matches': str([match.strings for match in matches])
                        }
                        all_matches.append(rule_matches)
            else:
                all_matches = "No YARA rules found."
    if not all_matches:
        all_matches = "No matches found."
                        

    return (json.dumps(all_matches, indent=4))

