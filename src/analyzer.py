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
import os

# Assumed to be in the same 'src' directory
from email_parser import EmailParser
from database_manager import DatabaseManager

# --- API & Risk Configuration ---
VIRUSTOTAL_API_KEY = '048cdca383ba19a08eb02cddc6179c90a4db4383f835defd9200e1f7a0f40aec'
ABUSEIPDB_API_KEY = '5ad63797b25a14f350d1cdd101b3bf549d40ff8cf16318395072a7253b68a7ae74a0b5c459626d42'

VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}
ABUSEIPDB_HEADERS = {
    "Key": ABUSEIPDB_API_KEY,
    "Accept": "application/json"
}

# --- Recalibrated Risk Scoring Constants (0-100 Scale) ---
RISK_FACTORS = {
    "MALICIOUS_ATTACHMENT": 95, "URL_MALICIOUS_TIER_1": 95, "AUTHENTICATION_FAILURE": 65,
    "MALICIOUS_IP_IN_URL": 75, "URL_MALICIOUS_TIER_2": 85, "HIGH_ABUSE_IP_SCORE": 70,
    "MALICIOUS_IP_VT": 70, "DOMAIN_AGE_VERY_NEW": 50, "HOMOGRAPH_DETECTED": 35,
    "URL_MALICIOUS_TIER_3": 75, "NON_MALICIOUS_IP_IN_URL": 20, "EXCESSIVE_SUBDOMAINS": 20,
    "PRIVATE_IP_DETECTED": 20, "DOMAIN_AGE_NEW": 25, "URL_MALICIOUS_TIER_4": 70,
    "SUSPICIOUS_KEYWORDS": 5, "DOMAIN_AGE_RECENT": 10, "LEGITIMATE_SENDER_AUTH": -10,
}

RISK_THRESHOLDS = {
    "VERY_HIGH": 95,
    "HIGH": 75,
    "MEDIUM": 20,
    "LOW": 10,
    "VERY_LOW": 1,
}

SUSPICIOUS_KEYWORDS = ['urgent', 'verify', 'password', 'account', 'suspended', 'invoice', 'payment', 'security alert',
                       'confirm', 'login']
HOMOGRAPH_CHARS = {'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'h', 'і': 'i', 'ј': 'j', 'ѕ': 's',
                   'ԁ': 'd', 'ɩ': 'l', 'ν': 'v', 'ѡ': 'w'}


# --- ThreatAnalyzer Class (No Changes) ---
class ThreatAnalyzer:
    def __init__(self):
        self.cache = {}
        print("💡 ThreatAnalyzer initialized with an empty cache.")

    def get_domain_age(self, hostname):
        cache_key = f"whois_{hostname}"
        if cache_key in self.cache:
            print(f"  -> [CACHE HIT] Using cached domain age for: {hostname}")
            return self.cache[cache_key]
        print(f"  -> [WHOIS LOOKUP] Querying registration date for: {hostname}")
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
        except Exception:
            print(f"  -> [WHOIS INFO] Could not determine age for {hostname}.")
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
        print(f"  -> [API CALL] Querying VirusTotal for URL: {url[:40]}...")
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


# --- Parsing & Static Analysis Functions (No Changes) ---
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


# --- Risk Scoring Algorithm (No Changes) ---
def calculate_risk_score(email_data, analysis_results):
    risk_score = 0
    risk_reasons = []

    # 1. Check sender authentication
    auth_header = email_data.get("auth_results", "")
    auth_results = parse_authentication_results(auth_header)
    if auth_results.get('spf') == 'pass' and auth_results.get('dkim') == 'pass' and auth_results.get('dmarc') == 'pass':
        risk_score += RISK_FACTORS["LEGITIMATE_SENDER_AUTH"]
        risk_reasons.append("Sender passed all authentication checks")
    if any(status in ['fail', 'softfail'] for status in [auth_results.get('spf'), auth_results.get('dmarc')]):
        risk_score += RISK_FACTORS["AUTHENTICATION_FAILURE"]
        risk_reasons.append("Sender failed SPF or DMARC authentication")

    # 2. Check attachments
    for result in analysis_results.get("attachments", []):
        if result and result.get("malicious", 0) > 0:
            risk_score += RISK_FACTORS["MALICIOUS_ATTACHMENT"]
            risk_reasons.append(f"Malicious attachment found ({result['name']})")
            break

    # 3. Check URLs
    for result in analysis_results.get("urls", []):
        if result["api_report"]:
            malicious_count = result["api_report"].get("malicious", 0)
            if malicious_count > 10:
                risk_score += RISK_FACTORS["URL_MALICIOUS_TIER_1"]; risk_reasons.append(
                    f"URL highly malicious by API ({malicious_count} vendors)")
            elif malicious_count >= 5:
                risk_score += RISK_FACTORS["URL_MALICIOUS_TIER_2"]; risk_reasons.append(
                    f"URL malicious by API ({malicious_count} vendors)")
            elif malicious_count >= 2:
                risk_score += RISK_FACTORS["URL_MALICIOUS_TIER_3"]; risk_reasons.append(
                    f"URL suspicious by API ({malicious_count} vendors)")
            elif malicious_count == 1:
                risk_score += RISK_FACTORS["URL_MALICIOUS_TIER_4"]; risk_reasons.append(f"URL flagged by 1 vendor")

        if "URL uses a direct IP address" in result["static_findings"]:
            ip_in_url = result.get("ip_in_url")
            is_ip_malicious = False
            for ip_report in analysis_results.get("public_ips", []):
                if ip_report['ip'] == ip_in_url:
                    if (ip_report["vt_report"] and ip_report["vt_report"].get("malicious", 0) > 0) or \
                            (ip_report["abuse_report"] and ip_report["abuse_report"].get("abuseConfidenceScore",
                                                                                         0) > 75):
                        is_ip_malicious = True
                        break
            if is_ip_malicious:
                risk_score += RISK_FACTORS["MALICIOUS_IP_IN_URL"]
                risk_reasons.append(f"URL contains a KNOWN MALICIOUS IP address ({ip_in_url})")
            else:
                risk_score += RISK_FACTORS["NON_MALICIOUS_IP_IN_URL"]
                risk_reasons.append(f"URL contains a direct IP address ({ip_in_url})")

        if "Excessive subdomains detected" in result["static_findings"]: risk_score += RISK_FACTORS[
            "EXCESSIVE_SUBDOMAINS"]; risk_reasons.append(f"URL has excessive subdomains")
        if any("Homograph character detected" in f for f in result["static_findings"]): risk_score += RISK_FACTORS[
            "HOMOGRAPH_DETECTED"]; risk_reasons.append(f"URL may contain homograph characters")

        age = result.get("domain_age_days")
        if age is not None and age < 9999:
            if age <= 30:
                risk_score += RISK_FACTORS["DOMAIN_AGE_VERY_NEW"]; risk_reasons.append(
                    f"Domain registered in the last month ({age} day(s) old)")
            elif age <= 182:
                risk_score += RISK_FACTORS["DOMAIN_AGE_NEW"]; risk_reasons.append(
                    f"Domain registered in the last 6 months ({age} day(s) old)")
            elif age <= 365:
                risk_score += RISK_FACTORS["DOMAIN_AGE_RECENT"]; risk_reasons.append(
                    f"Domain registered in the last year ({age} day(s) old)")

    # 4. Check IPs from body
    for result in analysis_results.get("public_ips", []):
        if result["vt_report"] and result["vt_report"].get("malicious", 0) > 0:
            risk_score += RISK_FACTORS["MALICIOUS_IP_VT"]
            risk_reasons.append(f"Malicious public IP detected by VirusTotal ({result['ip']})")
        if result["abuse_report"] and result["abuse_report"].get("abuseConfidenceScore", 0) > 75:
            risk_score += RISK_FACTORS["HIGH_ABUSE_IP_SCORE"]
            risk_reasons.append(f"High abuse score for public IP ({result['ip']})")

    for ip in analysis_results.get("private_ips", []):
        risk_score += RISK_FACTORS["PRIVATE_IP_DETECTED"]
        risk_reasons.append(f"Private IP address found in email body ({ip})")

    # 5. Check keywords
    email_content = (email_data.get("subject", "") + " " + email_data.get("body", "")).lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in email_content]
    if found_keywords:
        risk_score += RISK_FACTORS["SUSPICIOUS_KEYWORDS"]
        risk_reasons.append(f"Suspicious keywords found: {', '.join(set(found_keywords))}")

    # Determine final priority
    if risk_score >= RISK_THRESHOLDS["VERY_HIGH"]:
        priority = "Very High"
    elif risk_score >= RISK_THRESHOLDS["HIGH"]:
        priority = "High"
    elif risk_score >= RISK_THRESHOLDS["MEDIUM"]:
        priority = "Medium"
    elif risk_score >= RISK_THRESHOLDS["LOW"]:
        priority = "Low"
    elif risk_score >= RISK_THRESHOLDS["VERY_LOW"]:
        priority = "Very Low"
    else:
        priority = "Informational"

    return risk_score, priority, risk_reasons


def run_automated_analysis():
    """
    Cleans old data from tables, then fetches, analyzes, and saves new results.
    """
    print("--- Starting Automated Phishing Analysis ---")

    # Initialize components
    parser = EmailParser()
    db_manager = DatabaseManager()
    threat_analyzer = ThreatAnalyzer()

    db_manager.clear_all_data()

    messages = parser.fetch_emails(limit=100)
    if not messages:
        print("❌ No emails found. Please run 'send_test_email.py' first.")
        return

    print(f"✅ Found {len(messages)} email(s). Beginning analysis...")

    for i, msg_data in enumerate(messages):
        print(f"\n{'=' * 20} Analyzing Email #{i + 1} {'=' * 20}")
        email_data = parser.parse_email(msg_data)
        if not email_data: continue

        print(f"Subject: {email_data['subject']}")
        print(f"From: {email_data['sender']}")

        analysis_results = {"public_ips": [], "private_ips": [], "urls": [], "attachments": []}
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1_3}\b'
        ips_to_check = set(re.findall(ip_pattern, email_data['body']))
        for url in set(email_data['urls']):
            hostname = urlparse(url).hostname
            domain_age_days = threat_analyzer.get_domain_age(hostname) if hostname else 9999
            static_findings, ip_in_url = analyze_url_structure(url)
            if ip_in_url: ips_to_check.add(ip_in_url)
            api_report = parse_vt_analysis(threat_analyzer.check_url_reputation(url))
            analysis_results["urls"].append(
                {"url": url, "static_findings": static_findings, "domain_age_days": domain_age_days,
                 "api_report": api_report, "ip_in_url": ip_in_url})
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
            db_manager.save_analysis(email_data, analysis_results, score, priority)
            print(" -> ✅ Results successfully saved to database.")
        except Exception as e:
            print(f" -> ❌ Error saving to database: {e}")
        print("\n--- FINAL REPORT ---")
        print(f"Risk Score: {score}")
        print(f"Priority Level: {priority}")
        if reasons:
            print("Reasons for Score:")
            for reason in reasons: print(f"  - {reason}")
        else:
            print("No suspicious indicators found.")


if __name__ == "__main__":
    run_automated_analysis()