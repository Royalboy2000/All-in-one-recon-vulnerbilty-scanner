import requests
import json
import urllib3

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_settings(url, logger, db):
    target_url = f"{url}/rest/settings"
    logger.info(f"Checking for public settings at {target_url}...")
    try:
        response = requests.get(target_url, timeout=10, verify=False)
        if response.status_code == 200:
            try:
                data = response.json()
                logger.success(f"CRITICAL: Found public n8n settings at {target_url}")

                # Extract interesting fields
                findings = []
                findings.append(f"Version: {data.get('version', 'Unknown')}")
                findings.append(f"Instance ID: {data.get('instanceId', 'Unknown')}")

                telemetry = data.get('telemetry', {})
                if telemetry.get('enabled'):
                    findings.append("Telemetry: Enabled")

                features = data.get('features', {})
                if features.get('publicApi'):
                    findings.append("Feature: Public API Enabled")
                if features.get('communityNodes'):
                    findings.append("Feature: Community Nodes Enabled")

                execution = data.get('execution', {})
                findings.append(f"Execution Data Saved: {execution}")

                db.save_finding("n8n", url, "Configuration Exposure", findings)
                for f in findings:
                    logger.info(f)

                return True
            except json.JSONDecodeError:
                logger.warning(f"Settings endpoint {target_url} returned 200 but not valid JSON.")
        else:
            logger.info(f"Settings endpoint returned {response.status_code}")
    except Exception as e:
        logger.error(f"Error checking settings: {e}")
    return False

def check_config_js(url, logger, db):
    target_url = f"{url}/rest/config.js"
    logger.info(f"Checking for public config file at {target_url}...")
    try:
        response = requests.get(target_url, timeout=10, verify=False)
        if response.status_code == 200:
             logger.success(f"CRITICAL: Found public config.js at {target_url}")
             db.save_finding("n8n", url, "Config File Exposure", f"Accessible at {target_url}")
             return True
    except Exception as e:
        logger.error(f"Error checking config.js: {e}")
    return False

def check_api_docs(url, logger, db):
    target_url = f"{url}/api/v1/docs/"
    logger.info(f"Checking for API docs at {target_url}...")
    try:
        response = requests.get(target_url, timeout=10, verify=False)
        if response.status_code == 200:
             logger.success(f"Found public API documentation at {target_url}")
             db.save_finding("n8n", url, "API Documentation", f"Accessible at {target_url}")
             return True
    except Exception as e:
        logger.error(f"Error checking API docs: {e}")
    return False

def check_healthz(url, logger, db):
    target_url = f"{url}/healthz"
    logger.info(f"Checking health endpoint at {target_url}...")
    try:
        response = requests.get(target_url, timeout=10, verify=False)
        if response.status_code == 200:
             logger.success(f"Found health endpoint at {target_url}")
             db.save_finding("n8n", url, "Health Endpoint", f"Accessible at {target_url}")
             return True
    except Exception as e:
        logger.error(f"Error checking healthz: {e}")
    return False

def run(target, logger, db):
    # Ensure target has protocol
    if not target.startswith("http"):
        target = "http://" + target

    # Strip trailing slash
    if target.endswith("/"):
        target = target[:-1]

    logger.info(f"Starting n8n Reconnaissance on {target}")

    check_settings(target, logger, db)
    check_config_js(target, logger, db)
    check_api_docs(target, logger, db)
    check_healthz(target, logger, db)

    logger.success(f"n8n module finished for {target}")
