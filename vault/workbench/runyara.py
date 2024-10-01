import os
import yara
from tabulate import tabulate  # Make sure to install tabulate: pip install tabulate

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

                    # Store matches in the table-friendly format
                    if matches:
                        for match in matches[0]:
                            all_matches.append([
                                rule,
                                tags,
                                strings,
                                strings[0].identifier,
                                strings[0].instances,
                                strings[0].instances[0].offset,
                                strings[0].instances[0].matched_length
                            ])

    # If no matches were found
    if not all_matches:
        return "No matches found."

    # Define table headers
    headers = ["Matched Rule", "Tags", "Strings", "Identifier", "Instances", "Offset", "Matched Length"]

    # Return the matches as a table
    return tabulate(all_matches, headers=headers, tablefmt="grid")
