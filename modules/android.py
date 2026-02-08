import os
import re
from androguard.core.apk import APK
from colorama import Fore, Style

def analyze_manifest(apk, logger):
    logger.info("Analyzing AndroidManifest.xml...")
    permissions = apk.get_permissions()
    logger.success(f"Found {len(permissions)} permissions.")

    dangerous_permissions = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.INSTALL_PACKAGES",
    ]

    findings = []
    for perm in permissions:
        # perm is usually fully qualified like "android.permission.INTERNET"
        # but let's just check if the dangerous string is in it
        is_dangerous = False
        for dang in dangerous_permissions:
            if dang in perm:
                is_dangerous = True
                break

        if is_dangerous:
            logger.warning(f"Dangerous Permission: {perm}")
            findings.append(f"Dangerous: {perm}")
        else:
            findings.append(perm)

    return findings

def list_exported_activities(apk, logger):
    logger.info("Listing exported activities...")
    exported_activities = []

    manifest = apk.get_android_manifest_xml()
    if manifest is not None:
        # Namespace handling is tricky in lxml with default ns
        # Usually 'android' is bound to 'http://schemas.android.com/apk/res/android'
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        # Iterate over all activities
        # Using xpath or findall with namespace
        for activity in manifest.findall(".//activity"):
            name = activity.get('{http://schemas.android.com/apk/res/android}name')
            exported = activity.get('{http://schemas.android.com/apk/res/android}exported')

            # Check intent filters
            has_intent_filter = activity.find("intent-filter") is not None

            is_exported = False
            if exported == 'true':
                is_exported = True
            elif exported is None and has_intent_filter:
                # Default is true if intent-filter present (for older API levels, mostly relevant)
                # For newer API levels (17+), default is false unless explicitly true.
                # But as a scanner, we flag it as potential.
                is_exported = True
                name = f"{name} (Implicitly Exported)"

            if is_exported:
                exported_activities.append(name)
                logger.warning(f"Exported Activity: {name}")

    if not exported_activities:
        logger.info("No exported activities found.")

    return exported_activities

def find_secrets(apk, logger):
    logger.info("Hunting for secrets in APK files...")
    secrets = []

    # Regex patterns
    patterns = {
        "API Key": r"(?i)api_key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
        "Bearer Token": r"Bearer\s([a-zA-Z0-9_\-\.]+)",
        "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
        "Hardcoded Password": r"(?i)password['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9@#$%^&*]{6,})['\"]?",
        "Private Key": r"-----BEGIN PRIVATE KEY-----",
        "AWS Key": r"AKIA[0-9A-Z]{16}",
        "Generic Secret": r"(?i)secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{8,})['\"]?",
    }

    # Iterate through all files in APK
    # apk.get_files() returns a list of filenames
    for filename in apk.get_files():
        # Skip image/binary files usually to save time?
        # But secrets might be in binary files too.
        # We'll just try to decode as utf-8/ascii and search.

        try:
            content = apk.get_file(filename)
            # content is bytes. decoding might fail.
            try:
                text_content = content.decode('utf-8', errors='ignore')

                for name, pattern in patterns.items():
                    matches = re.finditer(pattern, text_content)
                    for match in matches:
                        extracted = match.group(0) # Get the whole match
                        # Truncate if too long
                        if len(extracted) > 100:
                            extracted = extracted[:100] + "..."

                        finding = f"Found {name} in {filename}: {extracted}"
                        # logger.warning(finding) # Too noisy if many
                        secrets.append(finding)
            except Exception:
                pass
        except Exception:
            pass

    if secrets:
        logger.warning(f"Found {len(secrets)} potential secrets.")
        # Print first few
        for s in secrets[:5]:
             logger.info(s)
    else:
        logger.info("No secrets found.")

    return secrets

def run(target, logger, db):
    if not os.path.exists(target):
        logger.error(f"File not found: {target}")
        return

    logger.info(f"Starting Android module on {target}")

    try:
        apk = APK(target)

        # 1. Manifest Analysis
        permissions = analyze_manifest(apk, logger)
        db.save_finding("ANDROID", target, "Permissions", permissions)

        # 2. Exported Activities
        exported = list_exported_activities(apk, logger)
        if exported:
            db.save_finding("ANDROID", target, "Exported Activities", exported)

        # 3. Secret Hunter
        secrets = find_secrets(apk, logger)
        if secrets:
            db.save_finding("ANDROID", target, "Secrets", secrets)

        logger.success(f"Android module finished for {target}")

    except Exception as e:
        logger.error(f"Error analyzing APK: {e}")
