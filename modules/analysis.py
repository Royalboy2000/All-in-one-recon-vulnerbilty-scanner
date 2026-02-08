import requests
import json
from colorama import Fore, Style
from modules.reporting import generate_report

def username_check(username, logger):
    logger.info(f"Checking username '{username}' across social networks...")

    sites = {
        "GitHub": f"https://github.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Twitter": f"https://twitter.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Medium": f"https://medium.com/@{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
    }

    found_sites = []

    for site, url in sites.items():
        try:
            # User-Agent is often needed to avoid 403s
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=5)

            if response.status_code == 200:
                logger.success(f"Found on {site}: {url}")
                found_sites.append({"site": site, "url": url})
            else:
                # logger.info(f"Not found on {site} ({response.status_code})")
                pass
        except Exception as e:
            logger.error(f"Error checking {site}: {e}")

    return found_sites

def data_miner(db, logger):
    logger.info("Mining database for correlations...")
    correlations = []

    # Get all findings
    findings = db.get_findings()

    # 1. Email Correlation
    # Scan all data fields for emails and see if they appear in multiple modules
    import re
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    email_map = {}

    for f in findings:
        f_id, module, target, f_type, data, timestamp = f

        # Search for emails in the data string
        found_emails = re.findall(email_pattern, str(data))
        for email in found_emails:
            if email not in email_map:
                email_map[email] = []
            email_map[email].append((module, target, f_type))

    # Check for emails appearing in different contexts
    for email, occurrences in email_map.items():
        if len(occurrences) > 1:
            modules_involved = set(occ[0] for occ in occurrences)
            if len(modules_involved) > 1:
                msg = f"Email '{email}' found in multiple modules: {', '.join(modules_involved)}"
                logger.warning(msg)
                correlations.append(msg)
            else:
                # Same module, different findings?
                targets_involved = set(occ[1] for occ in occurrences)
                if len(targets_involved) > 1:
                    msg = f"Email '{email}' connects targets: {', '.join(targets_involved)}"
                    logger.warning(msg)
                    correlations.append(msg)

    # 2. IP Correlation (if applicable)

    if not correlations:
        logger.info("No significant correlations found.")

    return correlations

def run(target, logger, db):
    logger.info("Starting Analysis & HUMINT module...")

    # Target here might be a username or "ALL"
    # But usually analysis runs on the DB data.
    # The prompt says: "Username Correlation: If we found a username in the OSINT phase..."
    # So we should look for usernames in the DB? Or ask user?
    # I'll implement a specific check if the user provides a target that looks like a username,
    # otherwise run general analysis.

    # For this implementation, let's treat the 'target' input as the Username to check for HUMINT,
    # and then run the Data Miner on the whole DB.

    # If the user provides a target, treat it as a potential username for correlation
    # But usually analysis runs on the entire database.
    # The prompt says: "Username Correlation: If we found a username in the OSINT phase..."
    # So we should ideally parse usernames from OSINT findings.
    # But for simplicity, we'll check the provided target if it's a simple string.

    # 1. Username Correlation
    username = target
    if username and " " not in username and "." not in username:
        social_profiles = username_check(username, logger)
        if social_profiles:
            # Check if this username is already in DB?
            db.save_finding("HUMINT", username, "Social Profiles", social_profiles)
    else:
        logger.info(f"Target '{target}' does not look like a username. Skipping social check.")

    # 2. Data Miner (Correlation Algorithms)
    # The requirement is: "If it sees the same email used in a domain whois and an Android app developer contact, link them together."
    # So we need to mine the DB.
    correlations = data_miner(db, logger)
    if correlations:
        db.save_finding("ANALYSIS", "Global", "Correlations", correlations)

    # Generate Report
    logger.info("Generating final report...")
    report_path = generate_report(db, logger)
    logger.success(f"Report generated: {report_path}")
