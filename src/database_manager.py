import sqlite3
import os
from datetime import datetime

class DatabaseManager:
    """
    Handles all interactions with the SQLite database.
    """
    def __init__(self, db_name="phishing_analysis.db"):
        data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
        os.makedirs(data_dir, exist_ok=True)
        db_path = os.path.join(data_dir, db_name)
        self.conn = sqlite3.connect(db_path)
        # PRAGMA foreign_keys = ON is crucial for ON DELETE CASCADE to work
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.create_tables()
        print(f"🗄️ Database initialized at: {db_path}")

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT, sender TEXT, risk_score INTEGER,
                priority TEXT, analysis_timestamp TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER, ioc_type TEXT, ioc_value TEXT,
                verdict TEXT, source TEXT,
                FOREIGN KEY(email_id) REFERENCES emails(id) ON DELETE CASCADE
            )
        ''')
        self.conn.commit()

    def clear_all_data(self):
        """
        Safely deletes all records. Deleting from 'emails' will cascade
        and delete all related 'iocs' because of the table schema.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM emails;")
            # Reset the autoincrement counter for clean IDs on the next run
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='emails';")
            self.conn.commit()
            print("🧹 Previous data cleared from database tables.")
        except sqlite3.Error as e:
            print(f"❌ Error clearing database tables: {e}. Please close any programs using the DB file.")

    def save_analysis(self, email_data, analysis_results, score, priority):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO emails (subject, sender, risk_score, priority, analysis_timestamp) VALUES (?, ?, ?, ?, ?)",
            (email_data['subject'], email_data['sender'], score, priority, timestamp)
        )
        email_id = cursor.lastrowid

        # Save IP results
        for ip_result in analysis_results.get("public_ips", []):
            if ip_result.get("vt_report"):
                vt_malicious = ip_result["vt_report"].get("malicious", 0) > 0
                cursor.execute("INSERT INTO iocs (email_id, ioc_type, ioc_value, verdict, source) VALUES (?, ?, ?, ?, ?)",
                               (email_id, 'ip', ip_result['ip'], 'Malicious' if vt_malicious else 'Safe', 'VirusTotal'))
            if ip_result.get("abuse_report"):
                abuse_malicious = ip_result["abuse_report"].get("abuseConfidenceScore", 0) > 75
                cursor.execute("INSERT INTO iocs (email_id, ioc_type, ioc_value, verdict, source) VALUES (?, ?, ?, ?, ?)",
                               (email_id, 'ip', ip_result['ip'], 'Malicious' if abuse_malicious else 'Safe', 'AbuseIPDB'))
        for ip in analysis_results.get("private_ips", []):
            cursor.execute("INSERT INTO iocs (email_id, ioc_type, ioc_value, verdict, source) VALUES (?, ?, ?, ?, ?)",
                           (email_id, 'ip', ip, 'Suspicious (Private)', 'Static Analysis'))
        # Save URL results
        for url_result in analysis_results.get("urls", []):
            malicious = url_result.get("api_report", {}).get("malicious", 0) > 0
            cursor.execute("INSERT INTO iocs (email_id, ioc_type, ioc_value, verdict, source) VALUES (?, ?, ?, ?, ?)",
                           (email_id, 'url', url_result['url'], 'Malicious' if malicious else 'Safe', 'VirusTotal'))
        # Save attachment results
        for att_result in analysis_results.get("attachments", []):
            malicious = att_result.get("malicious", 0) > 0
            # --- CORRECTED TYPO HERE ---
            cursor.execute("INSERT INTO iocs (email_id, ioc_type, ioc_value, verdict, source) VALUES (?, ?, ?, ?, ?)",
                           (email_id, 'hash', att_result['sha256'], 'Malicious' if malicious else 'Safe', 'VirusTotal'))
        self.conn.commit()
        return email_id

    def __del__(self):
        self.conn.close()
