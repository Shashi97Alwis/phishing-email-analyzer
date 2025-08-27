import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import pandas as pd
import time
import os

#Test Data Configuration
# Define the path to the test data file
TEST_DATA_FILE = os.path.join(os.path.dirname(__file__), "test_data", "test_emails.xlsx")


def load_test_cases_from_excel(filepath):
    """Reads email test cases from an Excel file."""
    try:
        # Read the excel file into a pandas DataFrame
        df = pd.read_excel(filepath)
        # Convert the DataFrame to a list of dictionaries (records)
        # Also, handle empty cells (which pandas reads as NaN) by converting them to None
        return df.where(pd.notna(df), None).to_dict('records')
    except FileNotFoundError:
        print(f"❌ Error: Test data file not found at {filepath}")
        return []
    except Exception as e:
        print(f"❌ Error reading Excel file: {e}")
        return []


def send_email(subject, sender, body, attachment_filename=None, auth_results=None):
    """Constructs and sends a single email to the MailHog SMTP server."""
    try:
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = 'analyst@soc.local'

        if auth_results:
            msg['Authentication-Results'] = auth_results

        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        if attachment_filename:
            # Assumes dummy files are also in the test_data directory
            attachment_path = os.path.join(os.path.dirname(TEST_DATA_FILE), attachment_filename)
            try:
                with open(attachment_path, 'rb') as attachment_file:
                    part = MIMEApplication(attachment_file.read(), Name=attachment_filename)
                part['Content-Disposition'] = f'attachment; filename="{attachment_filename}"'
                msg.attach(part)
            except FileNotFoundError:
                print(f"  -> Attachment file not found: {attachment_path}. Sending without attachment.")

        #Connect to MailHog on working port (1080)
        with smtplib.SMTP("localhost", 1080, timeout=10) as server:
            server.send_message(msg)
        print(f"✅ Successfully sent email: '{subject}'")
        return True
    except Exception as e:
        print(f"❌ Failed to send email: '{subject}'. Reason: {e}")
        return False


def generate_and_send_batch():
    """Loads test cases from Excel and sends them as emails."""
    print("\n--- Starting Batch Email Generation from Excel ---")

    test_cases = load_test_cases_from_excel(TEST_DATA_FILE)

    if not test_cases:
        print("Aborting: No test cases were loaded from the Excel file.")
        return []  # Return an empty list on failure

    #Loop through each row from the Excel file and send an email
    for case in test_cases:
        send_email(
            subject=case["Subject"],
            sender=case["Sender"],
            body=case["Body"],
            attachment_filename=case.get("AttachmentFilename"),
            auth_results=case.get("AuthHeader")
        )
        time.sleep(0.5)  # Small delay between emails

    print("\n--- Batch Email Generation Complete ---")
    return test_cases


if __name__ == "__main__":
    sent_emails = generate_and_send_batch()
    if sent_emails:
        print(f"\n🔍 Check the MailHog UI at http://localhost:8081 to see the {len(sent_emails)} generated emails.")

