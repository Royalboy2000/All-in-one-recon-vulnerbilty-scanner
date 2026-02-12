import requests
import re
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_wp_users(url, logger, db):
    logger.info(f"Checking for exposed WP users at {url}/wp-json/wp/v2/users...")
    try:
        response = requests.get(f"{url}/wp-json/wp/v2/users", timeout=10, verify=False)
        if response.status_code == 200:
            users = response.json()
            if users:
                user_list = [u['slug'] for u in users]
                logger.success(f"Found {len(user_list)} WP users: {', '.join(user_list)}")
                db.save_finding("WordPress", url, "User Enumeration", user_list)
                return True
    except Exception as e:
        logger.error(f"Error checking WP users: {e}")
    return False

def check_wp_plugins(url, logger, db):
    logger.info(f"Checking for common WP plugins at {url}...")
    plugins_to_check = [
        "contact-form-7", "wordpress-seo", "gravityforms", "woocommerce", "elementor",
        "jetpack", "wordfence", "wp-super-cache", "akismet"
    ]

    found_plugins = []

    # 1. Check HTML source for plugin paths
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for /wp-content/plugins/PLUGIN-NAME/
        links = soup.find_all(['link', 'script', 'img'])
        for tag in links:
            src = tag.get('href') or tag.get('src')
            if src and "wp-content/plugins/" in src:
                for plugin in plugins_to_check:
                    if f"/plugins/{plugin}/" in src and plugin not in found_plugins:
                        found_plugins.append(plugin)
                        logger.success(f"Found plugin: {plugin} (via source)")

    except Exception as e:
        logger.error(f"Error checking plugins via source: {e}")

    # 2. Check readme.txt for common plugins (Brute-force)
    # Only check if not already found to save requests
    for plugin in plugins_to_check:
        if plugin not in found_plugins:
            try:
                readme_url = f"{url}/wp-content/plugins/{plugin}/readme.txt"
                resp = requests.get(readme_url, timeout=5, verify=False)
                if resp.status_code == 200 and "Stable tag:" in resp.text:
                    found_plugins.append(plugin)
                    logger.success(f"Found plugin: {plugin} (via readme.txt)")
            except:
                pass

    if found_plugins:
        db.save_finding("WordPress", url, "Plugins Detected", found_plugins)

    return found_plugins

def check_wp_version(url, logger, db):
    logger.info(f"Checking WP version at {url}...")
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta = soup.find("meta", attrs={"name": "generator"})
        if meta and "WordPress" in meta.get("content", ""):
            version = meta.get("content")
            logger.success(f"WordPress Version: {version}")
            db.save_finding("WordPress", url, "Version", version)
            return version
    except Exception as e:
        logger.error(f"Error checking WP version: {e}")
    return None

def run(target, logger, db):
    if not target.startswith("http"):
        target = "http://" + target

    target = target.rstrip("/")

    logger.info(f"Starting WordPress module on {target}")

    check_wp_version(target, logger, db)
    get_wp_users(target, logger, db)
    check_wp_plugins(target, logger, db)

    logger.success(f"WordPress module finished for {target}")
