# src/email_parser.py

import requests
import re
import email
from email.header import decode_header


class EmailParser:
    def __init__(self, host="localhost", http_port=8081):
        self.api_url = f"http://{host}:{http_port}/api/v2"

    def fetch_emails(self, limit=100):
        """Fetches a list of full message objects from the MailHog API."""
        try:
            response = requests.get(f"{self.api_url}/messages?limit={limit}")
            response.raise_for_status()  # Raise an exception for bad status codes
            messages = response.json().get("items", [])
            return messages
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Error fetching emails from MailHog API: {e}")
            return []

    def parse_email(self, message_data):
        """Parses the content of an email from the API message object."""
        try:
            # CORRECTED LINE: The raw email data is in the 'Raw' -> 'Data' field.
            raw_email_data = message_data.get("Raw", {}).get("Data")

            if not raw_email_data:
                print("⚠️ Raw email data not found in the message object. Skipping.")
                return None

            # The email library expects a string to parse
            msg = email.message_from_string(raw_email_data)

            # Extract headers
            subject, encoding = decode_header(msg.get("Subject", "No Subject"))[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or "utf-8", 'ignore')
            sender = msg.get("From", "Unknown Sender")

            # Extract body and URLs
            body = ""
            urls = []
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    # We only care about the plain text part for URL extraction
                    if content_type == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode(errors='ignore')
                            # A more robust regex to find URLs
                            urls = re.findall(r'https?://[^\s"\'<>]+', body)
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors='ignore')
                    urls = re.findall(r'https?://[^\s"\'<>]+', body)

            # Extract attachments
            attachments = []
            for part in msg.walk():
                # Check if the part is an attachment
                if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            "name": filename,
                            "content": part.get_payload(decode=True)
                        })

            return {
                "subject": subject,
                "sender": sender,
                "body": body,
                "urls": urls,
                "attachments": attachments
            }

        except Exception as e:
            print(f"⚠️ A general error occurred during email parsing: {e}")
            return None


# --- This block only runs when you execute 'python email_parser.py' directly ---
if __name__ == "__main__":
    print("--- Running email_parser.py in standalone test mode ---")

    parser = EmailParser()
    messages = parser.fetch_emails(limit=5)

    if not messages:
        print("❌ No emails found. Ensure MailHog is running and contains emails.")
    else:
        print(f"✅ Found {len(messages)} email(s). Parsing...")
        for msg_data in messages:
            email_data = parser.parse_email(msg_data)
            if email_data:
                print(f"Subject: {email_data['subject']}")
                print(f"Sender: {email_data['sender']}")
                print(f"URLs Found: {len(email_data['urls'])}")
                print(f"Attachments: {[a['name'] for a in email_data['attachments']]}")
                print("-" * 50)