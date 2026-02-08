import requests
import json
import urllib3
from bs4 import BeautifulSoup

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_crt_sh(domain, logger):
    logger.info(f"Searching crt.sh for {domain}...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            try:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name_value = entry['name_value']
                    # Handle multi-line entries
                    for subdomain in name_value.split('\n'):
                        subdomains.add(subdomain.strip())
                logger.success(f"Found {len(subdomains)} unique subdomains.")
                return list(subdomains)
            except json.JSONDecodeError:
                 logger.error("Failed to parse JSON from crt.sh")
        else:
            logger.error(f"crt.sh returned status code {response.status_code}")
    except Exception as e:
        logger.error(f"Error querying crt.sh: {e}")
    return []

def detect_tech_stack(url, logger):
    logger.info(f"Detecting tech stack for {url}...")
    tech_stack = []
    target_url = url
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    try:
        response = requests.get(target_url, timeout=10, verify=False)
        headers = response.headers

        # Check headers
        if 'Server' in headers:
            tech_stack.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            tech_stack.append(f"X-Powered-By: {headers['X-Powered-By']}")

        # Check HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            tech_stack.append(f"Generator: {meta_generator.get('content')}")

        # Specific checks
        body_text = response.text.lower()
        if "wp-content" in body_text:
            tech_stack.append("CMS: WordPress")
        if "react" in body_text:
            tech_stack.append("Framework: React (Potential)")
        if "laravel" in body_text:
            tech_stack.append("Framework: Laravel (Potential)")
        if "django" in body_text:
            tech_stack.append("Framework: Django (Potential)")

        if tech_stack:
            logger.success(f"Tech stack detected: {', '.join(tech_stack)}")
        else:
            logger.info("No specific tech stack detected.")

        return tech_stack
    except Exception as e:
        logger.error(f"Error detecting tech stack: {e}")
    return []

def get_wayback_urls(domain, logger):
    logger.info(f"Querying Wayback Machine for {domain}...")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        response = requests.get(url, timeout=60)
        if response.status_code == 200:
            try:
                data = response.json()
                if data:
                    # First row is header if data is present
                    urls = [row[0] for row in data[1:]]
                    logger.success(f"Found {len(urls)} archived URLs.")
                    return urls
            except json.JSONDecodeError:
                 logger.error("Failed to parse JSON from Wayback Machine")
        else:
            logger.error(f"Wayback Machine returned status code {response.status_code}")
    except Exception as e:
        logger.error(f"Error querying Wayback Machine: {e}")
    return []

def google_dorks(domain, logger):
    logger.info(f"Generating Google Dorks for {domain}...")
    dorks = [
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:xml",
        f"site:{domain} filetype:conf",
        f"site:{domain} inurl:admin",
        f"site:{domain} intitle:index.of",
        f"site:{domain} intext:password",
    ]
    for dork in dorks:
        # Just print the dork URL for the user to click
        # In a real tool, we might automate this, but prompt says "Generates Google Search links for the user"
        logger.info(f"Dork: https://www.google.com/search?q={dork.replace(' ', '+')}")
    return dorks

def run(target, logger, db):
    logger.info(f"Starting OSINT module on {target}")

    # Normalize target
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    # 1. Certificate Search
    subdomains = get_crt_sh(domain, logger)
    if subdomains:
        db.save_finding("OSINT", domain, "Subdomains", subdomains)

    # 2. Tech Stack Detection
    tech_stack = detect_tech_stack(domain, logger)
    if tech_stack:
        db.save_finding("OSINT", domain, "Tech Stack", tech_stack)

    # 3. Wayback Machine
    wayback_urls = get_wayback_urls(domain, logger)
    if wayback_urls:
         # Filter interesting params
        interesting = [u for u in wayback_urls if "?" in u and ("id=" in u or "admin=" in u or "token=" in u or "key=" in u)]
        if interesting:
            logger.info(f"Found {len(interesting)} interesting URLs in Wayback Machine.")
            db.save_finding("OSINT", domain, "Wayback Interesting URLs", interesting)

        # Save sample
        if len(wayback_urls) < 100:
            db.save_finding("OSINT", domain, "Wayback URLs", wayback_urls)
        else:
             db.save_finding("OSINT", domain, "Wayback URLs (Sample 100)", wayback_urls[:100])

    # 4. Google Dorks
    dorks = google_dorks(domain, logger)
    db.save_finding("OSINT", domain, "Google Dorks", dorks)

    logger.success(f"OSINT module finished for {domain}")
