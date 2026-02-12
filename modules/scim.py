import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_scim_bridge(url, logger, db):
    logger.info(f"Checking for SCIM Bridge at {url}...")
    try:
        response = requests.get(url, timeout=10, verify=False)

        # Check headers
        if 'SCIM-Bridge-Version' in response.headers:
            logger.success(f"CRITICAL: Found 1Password SCIM Bridge! Version: {response.headers['SCIM-Bridge-Version']}")
            db.save_finding("SCIM", url, "SCIM Bridge Found", f"Version: {response.headers['SCIM-Bridge-Version']}")
            return True

        # Check body
        if "1Password SCIM Bridge" in response.text:
            logger.success("Found 1Password SCIM Bridge via body text")
            db.save_finding("SCIM", url, "SCIM Bridge Found", "Detected in HTML body")
            return True

        # Check standard endpoint
        scim_endpoint = f"{url}/scim/v2/Users"
        resp2 = requests.get(scim_endpoint, timeout=10, verify=False)
        if resp2.status_code == 401: # Auth required means endpoint exists
            logger.success(f"Found SCIM endpoint at {scim_endpoint} (401 Unauthorized)")
            db.save_finding("SCIM", url, "SCIM Endpoint", f"Found at {scim_endpoint}")
            return True

    except Exception as e:
        logger.error(f"Error checking SCIM Bridge: {e}")
    return False

def run(target, logger, db):
    if not target.startswith("http"):
        target = "http://" + target

    target = target.rstrip("/")
    logger.info(f"Starting SCIM module on {target}")

    check_scim_bridge(target, logger, db)

    logger.success(f"SCIM module finished for {target}")
