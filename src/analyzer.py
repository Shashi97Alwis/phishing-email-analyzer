import base64
import requests
import argparse
from datetime import datetime
import hashlib
import re
import ipaddress
from urllib.parse import urlparse
import whois
import io
from contextlib import redirect_stdout
import time

from email_parser import EmailParser
from database_manager import DatabaseManager

#API & Risk Configuration
VIRUSTOTAL_API_KEY = '048cdca383ba19a08eb02cddc6179c90a4db4383f835defd9200e1f7a0f40aec'
ABUSEIPDB_API_KEY = '5ad63797b25a14f350d1cdd101b3bf549d40ff8cf16318395072a7253b68a7ae74a0b5c459626d42'
URLSCAN_API_KEY = '01982916-00bf-728f-aebc-96dcd5e40bf2'

VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}
ABUSEIPDB_HEADERS = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
URLSCAN_HEADERS = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}

#Recalibrated Risk Scoring Constants
RISK_FACTORS = {
    "MALICIOUS_ATTACHMENT": 95, "URL_MALICIOUS_TIER_1": 95, "AUTHENTICATION_FAILURE": 65,
    "MALICIOUS_IP_IN_URL": 75, "URL_MALICIOUS_TIER_2": 85, "HIGH_ABUSE_IP_SCORE": 70,
    "MALICIOUS_IP_VT": 70, "DOMAIN_AGE_VERY_NEW": 50, "HOMOGRAPH_DETECTED": 35,
    "URL_MALICIOUS_TIER_3": 75, "NON_MALICIOUS_IP_IN_URL": 20, "EXCESSIVE_SUBDOMAINS": 20,
    "PRIVATE_IP_DETECTED": 20, "DOMAIN_AGE_NEW": 25, "URL_MALICIOUS_TIER_4": 70,
    "SUSPICIOUS_KEYWORDS": 5, "DOMAIN_AGE_RECENT": 10, "LEGITIMATE_SENDER_AUTH": -10,
    "LOW_REP_TLD": 30, "UNCOMMON_TLD": 10, "URLSCAN_CONFIRMED_PHISH": 40, "URLSCAN_MALICIOUS_VERDICT": 20,
}

RISK_THRESHOLDS = {"VERY_HIGH": 95, "HIGH": 75, "MEDIUM": 20, "LOW": 10, "VERY_LOW": 1}

HIGH_REP_TLDS = ['.com', '.org', '.net', '.gov', '.edu', '.mil', '.int', '.ca', '.uk', '.de', '.jp', '.fr', '.au',
                 '.us', '.ru', '.ch', '.it', '.nl', '.se', '.no', '.es']
LOW_REP_TLDS = ['.xyz', '.club', '.top', '.live', '.info', '.loan', '.gq', '.ga', '.cf', '.ml', '.work', '.gdn', '.biz',
                '.online', '.site', '.website', '.tech', '.store', '.space', '.icu']
SUSPICIOUS_KEYWORDS = ['urgent', 'verify', 'password', 'account', 'suspended', 'invoice', 'payment', 'security alert',
                       'confirm', 'login']
HOMOGRAPH_CHARS = {'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'h', 'і': 'i', 'ј': 'j', 'ѕ': 's',
                   'ԁ': 'd', 'ɩ': 'l', 'ν': 'v', 'ѡ': 'w'}


class ThreatAnalyzer:
    def __init__(self):
        self.cache = {}
        print("[INFO] ThreatAnalyzer initialized with an empty cache.")

    def get_domain_age(self, hostname):
        cache_key = f"whois_{hostname}"
        if cache_key in self.cache:
            print(f"  -> [CACHE HIT] Using cached domain age for: {hostname}")
            return self.cache[cache_key]
        safe_hostname = hostname.encode('ascii', 'ignore').decode('ascii')
        print(f"  -> [WHOIS LOOKUP] Querying registration date for: {safe_hostname}")
        for attempt in range(3):
            try:
                f = io.StringIO()
                with redirect_stdout(f):
                    w = whois.whois(hostname)
                creation_date = w.creation_date
                if isinstance(creation_date, list): creation_date = creation_date[0]
                if creation_date:
                    age = (datetime.now() - creation_date).days
                    self.cache[cache_key] = age
                    return age
                else:
                    break
            except Exception:
                print(f"  -> [WHOIS WARNING] Attempt {attempt + 1} failed for {safe_hostname}. Retrying in 2s...")
                time.sleep(2)
        print(f"  -> [WHOIS INFO] Could not determine age for {safe_hostname} after multiple attempts.")
        self.cache[cache_key] = 9999
        return 9999

    def check_ip_reputation(self, ip):
        cache_key = f"vt_ip_{ip}"
        if cache_key in self.cache:
            print(f"  -> [CACHE HIT] Using cached VirusTotal result for IP: {ip}")
            return self.cache[cache_key]
        print(f"  -> [API CALL] Querying VirusTotal for IP: {ip}")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        try:
            response = requests.get(url, headers=VT_HEADERS, timeout=10)
            response.raise_for_status()
            result = response.json()
            self.cache[cache_key] = result
            return result
        except requests.exceptions.RequestException as e:
            return self._handle_api_error(e, "VirusTotal")

    def check_ip_abuseipdb(self, ip):
        cache_key = f"abuse_ip_{ip}"
        if cache_key in self.cache:
            print(f"  -> [CACHE HIT] Using cached AbuseIPDB result for IP: {ip}")
            return self.cache[cache_key]
        print(f"  -> [API CALL] Querying AbuseIPDB for IP: {ip}")
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        try:
            response = requests.get(url, headers=ABUSEIPDB_HEADERS, params=params, timeout=10)
            response.raise_for_status()
            result = response.json()
            self.cache[cache_key] = result
            return result
        except requests.exceptions.RequestException as e:
            return self._handle_api_error(e, "AbuseIPDB")

    def check_url_reputation(self, url):
        cache_key = f"vt_url_{url}"
        if cache_key in self.cache:
            print(f"  -> [CACHE HIT] Using cached VirusTotal result for URL: {url[:40]}...")
            return self.cache[cache_key]
        safe_url_print = url.encode('ascii', 'ignore').decode('ascii')
        print(f"  -> [API CALL] Querying VirusTotal for URL: {safe_url_print[:40]}...")
        url_bytes = url.encode('utf-8')
        url_id = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        try:
            response = requests.get(api_url, headers=VT_HEADERS, timeout=10)
            response.raise_for_status()
            result = response.json()
            self.cache[cache_key] = result
            return result
        except requests.exceptions.RequestException as e:
            return self._handle_api_error(e, "VirusTotal")

    def check_file_reputation(self, file_hash):
        cache_key = f"vt_hash_{file_hash}"
        if cache_key in self.cache:
            print(f"  -> [CACHE HIT] Using cached VirusTotal result for hash: {file_hash[:10]}...")
            return self.cache[cache_key]
        print(f"  -> [API CALL] Querying VirusTotal for hash: {file_hash[:10]}...")
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        try:
            response = requests.get(url, headers=VT_HEADERS, timeout=10)
            response.raise_for_status()
            result = response.json()
            self.cache[cache_key] = result
            return result
        except requests.exceptions.RequestException as e:
            return self._handle_api_error(e, "VirusTotal")

    def _handle_api_error(self, error, service_name):
        if isinstance(error, requests.HTTPError):
            status_code = error.response.status_code
            if status_code == 401:
                print(f"  -> [API ERROR] Invalid API Key for {service_name}.")
            elif status_code == 429:
                print(f"  -> [API ERROR] Rate limit exceeded for {service_name}.")
            elif status_code == 404:
                return {"data": {"attributes": {"last_analysis_stats": {}}}}
            else:
                print(f"  -> [API ERROR] HTTP Error {status_code} from {service_name}.")
        elif isinstance(error, requests.ConnectionError):
            print(f"  -> [API ERROR] Network connection error for {service_name}.")
        elif isinstance(error, requests.Timeout):
            print(f"  -> [API ERROR] Request timed out for {service_name}.")
        else:
            print(f"  -> [API ERROR] An unexpected error occurred with {service_name}: {error}")
        return None

    def submit_url_to_urlscan(self, url_to_scan):
        if 'YOUR_URLSCAN_API_KEY_HERE' in URLSCAN_API_KEY or not URLSCAN_API_KEY:
            print("  -> [CONFIG ERROR] URLScan.io API key is not set. Skipping scan.")
            return None
        cache_key = f"urlscan_submit_{url_to_scan}"
        if cache_key in self.cache:
            print(f"  -> [CACHE HIT] Using cached URLScan submission for: {url_to_scan[:40]}...")
            return self.cache[cache_key]
        print(f"  -> [API CALL] Submitting URL to URLScan.io: {url_to_scan[:40]}...")
        data = {"url": url_to_scan, "visibility": "private"}
        try:
            response = requests.post("https://urlscan.io/api/v1/scan/", headers=URLSCAN_HEADERS, json=data, timeout=15)
            response.raise_for_status()
            result = response.json()
            if result.get("api"):
                self.cache[cache_key] = result["api"]
                return result["api"]
        except requests.exceptions.RequestException as e:
            return self._handle_api_error(e, "URLScan.io Submit")
        return None

    def get_urlscan_report(self, scan_api_url):
        cache_key = f"urlscan_report_{scan_api_url}"
        if cache_key in self.cache:
            print(f"  -> [CACHE HIT] Using cached URLScan report.")
            return self.cache[cache_key]
        print("  -> [INFO] Waiting for URLScan.io analysis to complete (can take 20-30s)...")
        for _ in range(12):
            time.sleep(5)
            try:
                response = requests.get(scan_api_url, timeout=10)
                if response.status_code == 200:
                    print("  -> [INFO] Scan complete. Fetching report.")
                    result = response.json()
                    self.cache[cache_key] = result
                    return result
            except requests.exceptions.RequestException:
                pass
        print("  -> [API ERROR] URLScan.io report timed out or failed to retrieve.")
        return None


def parse_abuseipdb_details(result):
    if not result or 'data' not in result: return {'error': 'No data from AbuseIPDB'}
    return result.get('data', {})


def parse_vt_analysis(result):
    if not result or 'data' not in result: return None
    return result.get('data', {}).get('attributes', {}).get('last_analysis_stats')


def analyze_url_structure(url):
    findings = []
    ip_in_hostname = None
    try:
        hostname = urlparse(url).hostname
        if not hostname: return findings, ip_in_hostname
        try:
            ip_obj = ipaddress.ip_address(hostname)
            findings.append("URL uses a direct IP address")
            ip_in_hostname = str(ip_obj)
        except ValueError:
            pass
        if hostname.count('.') > 3: findings.append("Excessive subdomains detected")
        if any(char in HOMOGRAPH_CHARS for char in hostname): findings.append("Homograph character detected")
    except Exception:
        pass
    return findings, ip_in_hostname


def parse_authentication_results(header_string):
    results = {}
    if not header_string: return results
    parts = header_string.split(';')
    for part in parts:
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            if key.lower() in ['spf', 'dkim', 'dmarc']:
                results[key.lower()] = value.split()[0].lower()
    return results


# --- UPDATED: Risk Scoring Algorithm to return a list of (reason, score) tuples ---
def calculate_risk_score(email_data, analysis_results):
    risk_reasons = []  # Will now be a list of tuples: (reason, score)

    # Helper to add a reason and its score
    def add_risk(factor_name, reason_text):
        score = RISK_FACTORS.get(factor_name, 0)
        risk_reasons.append((reason_text, score))

    auth_header = email_data.get("auth_results", "")
    auth_results = parse_authentication_results(auth_header)
    if auth_results.get('spf') == 'pass' and auth_results.get('dkim') == 'pass' and auth_results.get('dmarc') == 'pass':
        add_risk("LEGITIMATE_SENDER_AUTH", "Sender passed all authentication checks")
    if any(status in ['fail', 'softfail'] for status in [auth_results.get('spf'), auth_results.get('dmarc')]):
        add_risk("AUTHENTICATION_FAILURE", "Sender failed SPF or DMARC authentication")

    sender_email = email_data.get("sender", "")
    if sender_email and '@' in sender_email:
        sender_domain = sender_email.split('@')[-1].strip('>')
        tld = '.' + '.'.join(
            sender_domain.split('.')[-2:]) if ".co." in sender_domain or ".ac." in sender_domain else '.' + \
                                                                                                      sender_domain.split(
                                                                                                          '.')[-1]
        if tld in LOW_REP_TLDS:
            add_risk("LOW_REP_TLD", f"Sender uses a low-reputation TLD ({tld})")
        elif tld not in HIGH_REP_TLDS:
            add_risk("UNCOMMON_TLD", f"Sender uses an uncommon TLD ({tld})")

    for result in analysis_results.get("attachments", []):
        if result and result.get("malicious", 0) > 0:
            add_risk("MALICIOUS_ATTACHMENT", f"Malicious attachment found ({result['name']})")
            break

    for result in analysis_results.get("urls", []):
        if result["api_report"]:
            malicious_count = result["api_report"].get("malicious", 0)
            if malicious_count > 10:
                add_risk("URL_MALICIOUS_TIER_1", f"URL highly malicious by API ({malicious_count} vendors)")
            elif malicious_count >= 5:
                add_risk("URL_MALICIOUS_TIER_2", f"URL malicious by API ({malicious_count} vendors)")
            elif malicious_count >= 2:
                add_risk("URL_MALICIOUS_TIER_3", f"URL suspicious by API ({malicious_count} vendors)")
            elif malicious_count == 1:
                add_risk("URL_MALICIOUS_TIER_4", f"URL flagged by 1 vendor")

        if result.get("urlscan_report"):
            scan_verdicts = result["urlscan_report"].get("verdicts", {})
            if scan_verdicts.get("overall", {}).get("malicious"): add_risk("URLSCAN_MALICIOUS_VERDICT",
                                                                           "URLScan.io verdict is malicious")
            scan_brands = result["urlscan_report"].get("lists", {}).get("brand", [])
            if scan_brands: add_risk("URLSCAN_CONFIRMED_PHISH",
                                     f"URLScan.io detected impersonation of brands: {', '.join(scan_brands)}")

        if "URL uses a direct IP address" in result["static_findings"]:
            ip_in_url = result.get("ip_in_url")
            is_ip_malicious = False
            for ip_report in analysis_results.get("public_ips", []):
                if ip_report['ip'] == ip_in_url:
                    if (ip_report["vt_report"] and ip_report["vt_report"].get("malicious", 0) > 0) or \
                            (ip_report["abuse_report"] and ip_report["abuse_report"].get("abuseConfidenceScore",
                                                                                         0) > 75):
                        is_ip_malicious = True;
                        break
            if is_ip_malicious:
                add_risk("MALICIOUS_IP_IN_URL", f"URL contains a KNOWN MALICIOUS IP address ({ip_in_url})")
            else:
                add_risk("NON_MALICIOUS_IP_IN_URL", f"URL contains a direct IP address ({ip_in_url})")

        if "Excessive subdomains detected" in result["static_findings"]: add_risk("EXCESSIVE_SUBDOMAINS",
                                                                                  f"URL has excessive subdomains")
        if any("Homograph character detected" in f for f in result["static_findings"]): add_risk("HOMOGRAPH_DETECTED",
                                                                                                 f"URL may contain homograph characters")

        age = result.get("domain_age_days")
        if age is not None and age < 9999:
            if age <= 30:
                add_risk("DOMAIN_AGE_VERY_NEW", f"Domain registered in the last month ({age} day(s) old)")
            elif age <= 182:
                add_risk("DOMAIN_AGE_NEW", f"Domain registered in the last 6 months ({age} day(s) old)")
            elif age <= 365:
                add_risk("DOMAIN_AGE_RECENT", f"Domain registered in the last year ({age} day(s) old)")

    for result in analysis_results.get("public_ips", []):
        if result["vt_report"] and result["vt_report"].get("malicious", 0) > 0:
            add_risk("MALICIOUS_IP_VT", f"Malicious public IP detected by VirusTotal ({result['ip']})")
        if result["abuse_report"] and result["abuse_report"].get("abuseConfidenceScore", 0) > 75:
            add_risk("HIGH_ABUSE_IP_SCORE", f"High abuse score for public IP ({result['ip']})")

    for ip in analysis_results.get("private_ips", []):
        add_risk("PRIVATE_IP_DETECTED", f"Private IP address found in email body ({ip})")

    email_content = (email_data.get("subject", "") + " " + email_data.get("body", "")).lower()
    if any(kw in email_content for kw in SUSPICIOUS_KEYWORDS):
        add_risk("SUSPICIOUS_KEYWORDS",
                 f"Suspicious keywords found: {', '.join(set(kw for kw in SUSPICIOUS_KEYWORDS if kw in email_content))}")

    total_score = sum(score for reason, score in risk_reasons)

    if total_score >= RISK_THRESHOLDS["VERY_HIGH"]:
        priority = "Very High"
    elif total_score >= RISK_THRESHOLDS["HIGH"]:
        priority = "High"
    elif total_score >= RISK_THRESHOLDS["MEDIUM"]:
        priority = "Medium"
    elif total_score >= RISK_THRESHOLDS["LOW"]:
        priority = "Low"
    elif total_score >= RISK_THRESHOLDS["VERY_LOW"]:
        priority = "Very Low"
    else:
        priority = "Informational"

    return total_score, priority, risk_reasons


def run_automated_analysis():
    print("--- Starting Automated Phishing Analysis ---")
    parser = EmailParser()
    db_manager = DatabaseManager()
    threat_analyzer = ThreatAnalyzer()
    db_manager.clear_all_data()
    messages = parser.fetch_emails(limit=100)
    if not messages:
        print("[ERROR] No emails found. Please run 'send_test_email.py' first.")
        return

    print(f"[INFO] Found {len(messages)} email(s). Beginning analysis...")

    for i, msg_data in enumerate(messages):
        print(f"\n{'=' * 20} Analyzing Email #{i + 1} {'=' * 20}")
        email_data = parser.parse_email(msg_data)
        if not email_data: continue
        print(f"Subject: {email_data['subject']}")
        print(f"From: {email_data['sender']}")
        analysis_results = {"public_ips": [], "private_ips": [], "urls": [], "attachments": []}
        ips_to_check = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', email_data['body']))
        for url in set(email_data['urls']):
            hostname = urlparse(url).hostname
            domain_age_days = threat_analyzer.get_domain_age(hostname) if hostname else 9999
            static_findings, ip_in_url = analyze_url_structure(url)
            if ip_in_url: ips_to_check.add(ip_in_url)
            api_report = parse_vt_analysis(threat_analyzer.check_url_reputation(url))
            urlscan_report = None
            if api_report and api_report.get("malicious", 0) > 1:
                scan_api_url = threat_analyzer.submit_url_to_urlscan(url)
                if scan_api_url:
                    urlscan_report = threat_analyzer.get_urlscan_report(scan_api_url)
            analysis_results["urls"].append(
                {"url": url, "static_findings": static_findings, "domain_age_days": domain_age_days,
                 "api_report": api_report, "ip_in_url": ip_in_url, "urlscan_report": urlscan_report})
        for ip in ips_to_check:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    print(f"  -> [STATIC] Found private IP address: {ip}. Skipping API calls.")
                    analysis_results["private_ips"].append(ip)
                else:
                    vt_report = parse_vt_analysis(threat_analyzer.check_ip_reputation(ip))
                    abuse_report = parse_abuseipdb_details(threat_analyzer.check_ip_abuseipdb(ip))
                    analysis_results["public_ips"].append(
                        {"ip": ip, "vt_report": vt_report, "abuse_report": abuse_report})
            except ValueError:
                print(f"  -> [STATIC] Invalid IP address found in body: {ip}")
        for attachment in email_data['attachments']:
            file_hash = hashlib.sha256(attachment['content']).hexdigest()
            report = parse_vt_analysis(threat_analyzer.check_file_reputation(file_hash))
            analysis_results["attachments"].append({"name": attachment['name'], "sha256": file_hash, **(report or {})})
        score, priority, reasons = calculate_risk_score(email_data, analysis_results)
        try:
            db_manager.save_analysis(email_data, analysis_results, score, priority, reasons)  # Pass reasons to save
            print(" -> [DB SUCCESS] Results successfully saved to database.")
        except Exception as e:
            print(f" -> [DB ERROR] Error saving to database: {e}")
        print("\n--- FINAL REPORT ---")
        print(f"Risk Score: {score}")
        print(f"Priority Level: {priority}")
        if reasons:
            print("Reasons for Score:")
            for reason, r_score in reasons: print(f"  - {reason} ({r_score})")
        else:
            print("No suspicious indicators found.")


if __name__ == "__main__":
    run_automated_analysis()
