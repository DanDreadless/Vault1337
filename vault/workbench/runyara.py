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

                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    matches = rule.match(data=file_data)
                except Exception as e:
                    logger.error("Error scanning %s with %s: %s", file_path, rule_path, e)
                    continue

                for match in matches:
                    tags = ', '.join(match.tags) if match.tags else ''
                    if match.strings:
                        for string_match in match.strings:
                            for instance in string_match.instances:
                                all_matches.append([
                                    match.rule,
                                    tags,
                                    string_match.identifier,
                                    hex(instance.offset),
                                    instance.matched_length,
                                ])
                    else:
                        # Condition-only rule — matched without any string patterns.
                        all_matches.append([match.rule, tags, '(condition only)', '', ''])

    if not all_matches:
        return "No matches found."

    headers = ["Rule", "Tags", "String", "Offset", "Length"]
    return tabulate(all_matches, headers=headers, tablefmt="grid")
