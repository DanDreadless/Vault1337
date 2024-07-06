import yara

def run_yara(file_path):
    rules_path = 'vault/yara-rules/'
    rules = yara.compile(rules_path)
    matches = rules.match(file_path)
    return matches