import os
import re

# Common secret regex patterns
PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"[0-9a-zA-Z/+]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
    "Private Key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    "Generic Token": r"bearer [a-zA-Z0-9\\-\\_\\.]+",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
}

def scan_file(filepath, logger, db):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
            for name, pattern in PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    unique_matches = list(set(matches))
                    logger.success(f"Found {len(unique_matches)} {name}(s) in {filepath}")
                    db.save_finding("Secrets", filepath, name, unique_matches)
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")

def run(target, logger, db):
    logger.info(f"Starting Secrets Scanner on {target}")

    if os.path.isfile(target):
        scan_file(target, logger, db)
    elif os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            for file in files:
                filepath = os.path.join(root, file)
                scan_file(filepath, logger, db)
    else:
        logger.error(f"Target {target} is not a valid file or directory.")

    logger.success(f"Secrets module finished for {target}")
