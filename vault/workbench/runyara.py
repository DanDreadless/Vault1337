import os
import yara
from tabulate import tabulate  # Install with: pip install tabulate

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
                        for match in matches:
                            for string in match.strings:
                                offset, identifier, data = string  # Unpack the tuple
                                all_matches.append([
                                    rule_path,
                                    match.rule,         # The matched rule name
                                    hex(offset),        # Offset where the match occurred (as hex)
                                    identifier,         # String ID
                                    data.decode(errors="replace")  # The matched value (decoded)
                                ])

    # If no matches were found
    if not all_matches:
        return "No matches found."

    # Define table headers
    headers = ["Rule File", "Matched Rule", "Offset", "String ID", "Matched Value"]

    # Return the matches as a table
    return tabulate(all_matches, headers=headers, tablefmt="grid")
