import os
import logging
import yara
from tabulate import tabulate
from django.conf import settings

logger = logging.getLogger(__name__)

MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB


def run_yara(file_path):
    rules_path = settings.YARA_RULES_DIR

    file_size = os.path.getsize(file_path)
    if file_size > MAX_READ_BYTES:
        mb = round(file_size / (1024 * 1024))
        return f"Error: File is too large to scan ({mb} MB). Maximum is 10 MB."

    all_matches = []

    for root, dirs, files in os.walk(rules_path):
        for file in files:
            if file.endswith('.yar'):
                rule_path = os.path.join(root, file)

                try:
                    rule = yara.compile(filepath=rule_path)
                except yara.SyntaxError as e:
                    logger.error("Error compiling %s: %s", rule_path, e)
                    continue

                with open(file_path, 'rb') as f:
                    file_data = f.read()

                    matches = rule.match(data=file_data)

                    if matches:
                        all_matches.append([
                            matches,
                            matches[0].rule,
                            matches[0].tags,
                            matches[0].strings,
                            matches[0].strings[0].identifier,
                            matches[0].strings[0].instances,
                            matches[0].strings[0].instances[0].offset,
                            matches[0].strings[0].instances[0].matched_length
                        ])

    if not all_matches:
        return "No matches found."

    headers = ["Matches", "Matched Rule", "Tags", "Strings", "Identifier", "Instances", "Offset", "Matched Length"]

    return tabulate(all_matches, headers=headers, tablefmt="grid")
