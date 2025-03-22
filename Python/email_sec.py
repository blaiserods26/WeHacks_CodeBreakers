import imaplib
import email
import os
import requests
import hashlib
import time
import dns.resolver
import re
import base64
from email import policy
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
import urllib.parse

# Email configuration
IMAP_SERVER = "imap.gmail.com"
SMTP_SERVER = "smtp.gmail.com"
EMAIL_ACCOUNT = "contineo.crce@gmail.com"
EMAIL_PASSWORD = "omle qjyw vlgr cvyn"
ALLOWED_DOMAIN = "@gmail.com"
CHECK_INTERVAL = 5  # Check for new emails every 30 seconds

# Gmail API configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = "./credentials.json"  # You'll need to create this file
API_KEY = "AIzaSyCEp3ZGODSMkSUXnecWTo8DXfdyRi_dVdQ"

# Attachment handling configuration
ATTACHMENT_SAVE_PATH = "./attachments"
QUARANTINE_PATH = "./quarantine"
VT_API_KEY = "1b817d672b36edeb26c65ce8e63836a1bf37d936bceb9fb27e07e53272d31366"
VT_API_ENDPOINT = "https://www.virustotal.com/vtapi/v2/file/report"

# Ensure directories exist
for directory in [ATTACHMENT_SAVE_PATH, QUARANTINE_PATH]:
    if not os.path.exists(directory):
        os.makedirs(directory)

class EmailSecurityAnalyzer:
    def __init__(self):
        self.spf_score = 0
        self.dkim_score = 0
        self.dmarc_score = 0

    def analyze_spf(self, domain):
        """Analyze SPF record for the domain."""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_records = [txt_record.to_text() for txt_record in answers if 'v=spf1' in txt_record.to_text()]

            if not spf_records:
                return {
                    'exists': False,
                    'score': 0,
                    'grade': 'F',
                    'details': 'SPF record not found',
                    'recommendations': ['Implement a valid SPF record for your domain.']
                }

            # Use the first SPF record found
            spf_record = spf_records[0]
            score = 100
            issues = []
            recommendations = []

            # Evaluate SPF mechanism
            if ' -all' in spf_record:
                score += 5  # Hard fail provides strong enforcement
            elif ' ~all' in spf_record:
                score -= 20  # Soft fail mechanism is less secure
                issues.append("Soft fail mechanism (~all) detected in SPF record.")
                recommendations.append("Use hard fail (-all) for stricter enforcement.")
            else:
                score -= 40
                issues.append("No fail mechanism specified in SPF record.")
                recommendations.append("Specify a fail mechanism such as '-all'.")

            # Check for excessive DNS lookups (SPF DNS lookup limit is 10)
            lookup_count = len(re.findall(r'(include|a|mx|ptr|exists):', spf_record))
            if lookup_count > 10:
                score -= 30
                issues.append(f"Excessive DNS lookups in SPF record ({lookup_count} lookups).")
                recommendations.append("Reduce the number of DNS lookups to comply with SPF limits.")

            # Determine grade
            grade = 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'

            return {
                'exists': True,
                'score': score,
                'grade': grade,
                'record': spf_record,
                'issues': issues,
                'recommendations': recommendations
            }

        except dns.resolver.NoAnswer:
            return {
                'exists': False,
                'score': 0,
                'grade': 'F',
                'details': 'No TXT records found in DNS.',
                'recommendations': ['Verify DNS entries for the domain.']
            }
        except dns.resolver.NXDOMAIN:
            return {
                'exists': False,
                'score': 0,
                'grade': 'F',
                'details': 'Domain does not exist.',
                'recommendations': ['Provide a valid domain name.']
            }
        except Exception as e:
            return {
                'exists': False,
                'score': 0,
                'grade': 'F',
                'details': str(e),
                'recommendations': ['Check your DNS configuration and network connectivity.']
            }

    def analyze_dkim(self, domain, selector='default'):
        """Analyze DKIM record for the domain."""
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            dkim_records = [txt_record.to_text() for txt_record in answers if 'v=DKIM1' in txt_record.to_text()]

            if not dkim_records:
                return {
                    'exists': False,
                    'score': 0,
                    'grade': 'F',
                    'details': f"No DKIM record found for selector '{selector}'.",
                    'recommendations': ['Implement a DKIM record for your domain.']
                }

            dkim_record = dkim_records[0]
            score = 100
            issues = []
            recommendations = []

            # Extract key length
            key_match = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_record)
            if key_match:
                try:
                    key_data = base64.b64decode(key_match.group(1))
                    key_length = len(key_data) * 8
                    if key_length < 1024:
                        score -= 40
                        issues.append("Very weak DKIM key strength (<1024 bits).")
                        recommendations.append("Use at least 2048-bit keys for DKIM.")
                    elif key_length < 2048:
                        score -= 20
                        issues.append("Moderate DKIM key strength (<2048 bits).")
                        recommendations.append("Upgrade to 2048-bit DKIM keys.")
                except Exception:
                    issues.append("Failed to parse DKIM key.")
                    recommendations.append("Verify DKIM key format and correctness.")
            else:
                score -= 40
                issues.append("Public key not found in DKIM record.")
                recommendations.append("Ensure the DKIM record contains a valid public key.")

            grade = 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'

            return {
                'exists': True,
                'score': score,
                'grade': grade,
                'record': dkim_record,
                'issues': issues,
                'recommendations': recommendations
            }

        except Exception as e:
            return {
                'exists': False,
                'score': 0,
                'grade': 'F',
                'details': str(e),
                'recommendations': ['Check DKIM configuration for your domain.']
            }

    def analyze_dmarc(self, domain):
        """Analyze DMARC record for the domain."""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [txt_record.to_text() for txt_record in answers if 'v=DMARC1' in txt_record.to_text()]

            if not dmarc_records:
                return {
                    'exists': False,
                    'score': 0,
                    'grade': 'F',
                    'details': 'No DMARC record found.',
                    'recommendations': ['Implement a DMARC policy for your domain.']
                }

            dmarc_record = dmarc_records[0]
            score = 100
            issues = []
            recommendations = []

            # Check policy settings
            if 'p=reject' in dmarc_record:
                score += 10
            elif 'p=quarantine' in dmarc_record:
                score -= 20
                issues.append("DMARC policy set to quarantine.")
                recommendations.append("Set DMARC policy to 'reject' for stronger enforcement.")
            elif 'p=none' in dmarc_record:
                score -= 50
                issues.append("DMARC policy set to none.")
                recommendations.append("Set DMARC policy to 'reject' for better security.")

            # Reporting settings
            if 'rua=' not in dmarc_record:
                score -= 10
                issues.append("No aggregate reporting (rua) specified.")
                recommendations.append("Add aggregate reporting URI (rua) to your DMARC record.")
            if 'ruf=' not in dmarc_record:
                recommendations.append("Add forensic reporting URI (ruf) to your DMARC record.")

            grade = 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'

            return {
                'exists': True,
                'score': score,
                'grade': grade,
                'record': dmarc_record,
                'issues': issues,
                'recommendations': recommendations
            }

        except Exception as e:
            return {
                'exists': False,
                'score': 0,
                'grade': 'F',
                'details': str(e),
                'recommendations': ['Check DMARC configuration for your domain.']
            }

    def extract_domain_from_email(self, email):
        """Extract domain from email address."""
        match = re.search(r'@([a-zA-Z0-9.-]+)', email)
        return match.group(1).lower() if match else None

    def comprehensive_email_security_analysis(self, email):
        """Perform a comprehensive email security analysis."""
        domain = self.extract_domain_from_email(email)

        if not domain:
            return {
                'error': 'Invalid email format.',
                'recommendations': ['Provide a valid email address for analysis.']
            }

        # Analyze SPF, DKIM, and DMARC
        spf_result = self.analyze_spf(domain)
        dkim_result = self.analyze_dkim(domain)
        dmarc_result = self.analyze_dmarc(domain)

        # Calculate overall score
        overall_score = (
            spf_result.get('score', 0) * 0.3 +
            dkim_result.get('score', 0) * 0.3 +
            dmarc_result.get('score', 0) * 0.4
        )

        # Determine grade
        overall_grade = 'A' if overall_score >= 90 else 'B' if overall_score >= 80 else 'C' if overall_score >= 70 else 'D' if overall_score >= 60 else 'F'

        return {
            'email': email,
            'domain': domain,
            'overall_score': round(overall_score, 2),
            'overall_grade': overall_grade,
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result,
        }

def analyze_links(email_body):
    """Analyze links in email body for potential phishing."""
    soup = BeautifulSoup(email_body, 'html.parser')
    links = soup.find_all('a')
    suspicious_links = []
    
    for link in links:
        href = link.get('href')
        if href:
            # Check for common phishing indicators
            suspicious = False
            reasons = []
            
            # Check for IP addresses in URL
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', href):
                suspicious = True
                reasons.append("Contains IP address")
            
            # Check for misleading domains
            parsed_url = urllib.parse.urlparse(href)
            if parsed_url.netloc:
                if re.search(r'(paypal|google|microsoft|apple|amazon)', parsed_url.netloc, re.I):
                    if not re.search(r'\.(com|net|org)$', parsed_url.netloc):
                        suspicious = True
                        reasons.append("Potentially spoofed domain")
            
            # Check for suspicious TLDs
            if re.search(r'\.(xyz|tk|ml|ga|cf)$', href):
                suspicious = True
                reasons.append("Suspicious TLD")
            
            if suspicious:
                suspicious_links.append({
                    "url": href,
                    "reasons": reasons
                })
    
    return {
        "total_links": len(links),
        "suspicious_links": suspicious_links,
        "risk_score": len(suspicious_links) * 25 if suspicious_links else 0
    }

def get_gmail_service(credentials_json):
    """Get Gmail API service instance."""
    try:
        # Load credentials from the JSON passed from the website
        credentials = Credentials.from_authorized_user_info(credentials_json, SCOPES)
        
        # If credentials are expired and can be refreshed, refresh them
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            
        service = build('gmail', 'v1', credentials=credentials)
        return service
    except Exception as e:
        return {"error": f"Failed to build Gmail service: {str(e)}"}

def process_email_content(service, message_id):
    """Process email content and return analysis results."""
    try:
        # Get the email message
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        
        # Extract email headers
        headers = message['payload']['headers']
        sender = next(h['value'] for h in headers if h['name'].lower() == 'from')
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        
        # Extract sender email
        sender_email = re.search(r'<(.+?)>', sender)
        sender_email = sender_email.group(1) if sender_email else sender
        
        # Initialize security analyzer
        analyzer = EmailSecurityAnalyzer()
        security_results = analyzer.comprehensive_email_security_analysis(sender_email)
        
        # Process email body
        body = ""
        if 'parts' in message['payload']:
            for part in message['payload']['parts']:
                if part['mimeType'] in ['text/plain', 'text/html']:
                    body = base64.urlsafe_b64decode(part['body']['data']).decode()
                    break
        
        # Analyze links in body
        link_analysis = analyze_links(body)
        
        # Process attachments
        attachment_results = {}
        if 'parts' in message['payload']:
            for part in message['payload']['parts']:
                if 'filename' in part and part['filename']:
                    filename = part['filename']
                    if 'data' in part['body']:
                        attachment_data = base64.urlsafe_b64decode(part['body']['data'])
                    elif 'attachmentId' in part['body']:
                        attachment = service.users().messages().attachments().get(
                            userId='me', messageId=message_id, id=part['body']['attachmentId']
                        ).execute()
                        attachment_data = base64.urlsafe_b64decode(attachment['data'])
                    
                    # Save and scan attachment
                    temp_path = os.path.join(ATTACHMENT_SAVE_PATH, "temp_" + filename)
                    with open(temp_path, "wb") as f:
                        f.write(attachment_data)
                    
                    is_safe, scan_details = scan_file_virustotal(temp_path)
                    attachment_results[filename] = {
                        "status": "Safe" if is_safe else "Suspicious",
                        "details": scan_details
                    }
        
        # Prepare JSON response
        analysis_result = {
            "email_info": {
                "sender": sender,
                "subject": subject,
                "timestamp": message['internalDate']
            },
            "security_analysis": security_results,
            "link_analysis": link_analysis,
            "attachment_analysis": attachment_results,
            "overall_risk_score": calculate_overall_risk(
                security_results['overall_score'],
                link_analysis['risk_score'],
                len([a for a in attachment_results.values() if a['status'] == 'Suspicious'])
            )
        }
        
        return analysis_result
        
    except Exception as e:
        return {"error": f"Failed to process email: {str(e)}"}

def calculate_overall_risk(security_score, link_risk_score, suspicious_attachments):
    """Calculate overall risk score."""
    # Convert security score to risk (100 - security_score)
    security_risk = 100 - security_score
    
    # Weight the components
    weighted_security = security_risk * 0.4
    weighted_links = link_risk_score * 0.3
    weighted_attachments = (suspicious_attachments * 25) * 0.3
    
    total_risk = weighted_security + weighted_links + weighted_attachments
    return min(100, total_risk)  # Cap at 100

def analyze_emails(credentials):
    """Main function to analyze emails and return results."""
    try:
        service = get_gmail_service(credentials)
        if "error" in service:
            return service
        
        # Get recent messages
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        
        if not messages:
            return {"message": "No emails found."}
        
        # Process each email
        analysis_results = []
        for message in messages:
            result = process_email_content(service, message['id'])
            analysis_results.append(result)
        
        return {
            "status": "success",
            "total_emails_analyzed": len(analysis_results),
            "results": analysis_results
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

def run_email_analysis_tool():
    """Interactive email analysis tool."""
    print("Email Security Analysis Tool")
    while True:
        email = input("Enter an email address to analyze: ")
        analyzer = EmailSecurityAnalyzer()

        # while True:
        if email.lower() == 'exit':
            print("Exiting the tool.")
            break

        result = analyzer.comprehensive_email_security_analysis(email)
        print("\n--- Analysis Results ---")
        if 'error' in result:
            print(result['error'])
            continue

        print(f"Email: {result['email']}")
        print(f"Domain: {result['domain']}")
        print(f"Overall Score: {result['overall_score']} (Grade: {result['overall_grade']}) \n")

        # SPF Analysis
        spf = result['spf']
        print("SPF Analysis:")
        print(f"  Score: {spf['score']} (Grade: {spf['grade']})")
        if spf.get('issues'):
            print(f"  Issues: {', '.join(spf['issues'])}")
        if spf.get('recommendations'):
            print(f"  Recommendations: {', '.join(spf['recommendations'])}")

        # DKIM Analysis
        dkim = result['dkim']
        print("\nDKIM Analysis:")
        print(f"  Score: {dkim['score']} (Grade: {dkim['grade']})")
        if dkim.get('issues'):
            print(f"  Issues: {', '.join(dkim['issues'])}")
        if dkim.get('recommendations'):
            print(f"  Recommendations: {', '.join(dkim['recommendations'])}")

        # DMARC Analysis
        dmarc = result['dmarc']
        print("\nDMARC Analysis:")
        print(f"  Score: {dmarc['score']} (Grade: {dmarc['grade']})")
        if dmarc.get('issues'):
            print(f"  Issues: {', '.join(dmarc['issues'])}")
        if dmarc.get('recommendations'):
            print(f"  Recommendations: {', '.join(dmarc['recommendations'])}")

        print("\n-------------------------\n")

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_file_virustotal(file_path):
    """Scan a file using VirusTotal API."""
    file_hash = get_file_hash(file_path)

    params = {
        'apikey': VT_API_KEY,
        'resource': file_hash
    }

    try:
        response = requests.get(VT_API_ENDPOINT, params=params)
        if response.status_code == 200:
            result = response.json()

            # Check if the file has been scanned before
            if result.get('response_code') == 0:
                print(f"File {os.path.basename(file_path)} not found in VirusTotal database")
                return True, "File not found in database"

            # Get detection ratio
            positives = result.get('positives', 0)
            total = result.get('total', 0)

            if positives == 0:
                return True, f"Clean (0/{total} detections)"
            else:
                return False, f"Suspicious ({positives}/{total} detections)"

        elif response.status_code == 204:
            print("API rate limit exceeded. Waiting 60 seconds...")
            time.sleep(60)
            return scan_file_virustotal(file_path)
        else:
            print(f"Error: API returned status code {response.status_code}")
            return None, "API error"

    except Exception as e:
        print(f"Error scanning file: {e}")
        return None, f"Error: {str(e)}"


def handle_attachment(part, filename, sender_email):
    """Save and scan attachment, returning True if file is safe."""
    temp_path = os.path.join(ATTACHMENT_SAVE_PATH, "temp_" + filename)

    # Save file temporarily
    with open(temp_path, "wb") as f:
        f.write(part.get_payload(decode=True))

    # Scan the file
    print(f"Scanning {filename} from {sender_email}...")
    is_safe, scan_details = scan_file_virustotal(temp_path)

    if is_safe:
        # Move to regular attachment folder
        final_path = os.path.join(ATTACHMENT_SAVE_PATH, filename)
        os.rename(temp_path, final_path)
        print(f"File is clean: {scan_details}")
        return True
    if is_safe is False:
        # Move to quarantine
        quarantine_path = os.path.join(QUARANTINE_PATH, filename)
        os.rename(temp_path, quarantine_path)
        print(f"⚠️ File is suspicious: {scan_details}")
        print(f"File moved to quarantine: {quarantine_path}")
        return False
    else:
        # In case of scanning error, err on the side of caution
        quarantine_path = os.path.join(QUARANTINE_PATH, filename)
        os.rename(temp_path, quarantine_path)
        print(f"⚠️ Scan error: {scan_details}")
        print(f"File moved to quarantine: {quarantine_path}")
        return False

def send_analysis_report(receiver_email, security_analysis, attachment_results):
    """Send analysis report email."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_ACCOUNT
        msg["To"] = receiver_email
        msg["Subject"] = "Email Security Analysis Report"

        # Create the email body with security analysis results
        body = "Email Security Analysis Report\n\n"
        body += f"Analyzed Email: {security_analysis['email']}\n"
        body += f"Domain: {security_analysis['domain']}\n"
        body += f"Overall Security Score: {security_analysis['overall_score']} (Grade: {security_analysis['overall_grade']})\n\n"

        # Add SPF, DKIM, DMARC details
        for protocol in ['SPF', 'DKIM', 'DMARC']:
            result = security_analysis[protocol.lower()]
            body += f"{protocol} Analysis:\n"
            body += f"  Score: {result['score']} (Grade: {result['grade']})\n"
            if result.get('issues'):
                body += f"  Issues: {', '.join(result['issues'])}\n"
            if result.get('recommendations'):
                body += f"  Recommendations: {', '.join(result['recommendations'])}\n"
            body += "\n"

        # Add attachment analysis results
        if attachment_results:
            body += "\nAttachment Analysis:\n"
            for filename, result in attachment_results.items():
                body += f"\nFile: {filename}\n"
                body += f"Status: {result['status']}\n"
                if 'details' in result:
                    body += f"Details: {result['details']}\n"

        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, 587)
        server.starttls()
        server.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ACCOUNT, receiver_email, msg.as_string())
        server.quit()

        print(f"Analysis report sent to {receiver_email}")
    except Exception as e:
        print("Error sending analysis report:", e)

def send_security_alert(sender_email, security_results):
    """Send security alert email to the sender."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_ACCOUNT
        msg["To"] = sender_email
        msg["Subject"] = "Security Alert: Your Email Was Not Secure"

        # Create the email body with security analysis results
        body = "Security Alert: Your Email Was Not Secure\n\n"
        body += f"Analyzed Email: {security_results['email']}\n"
        body += f"Domain: {security_results['domain']}\n"
        body += f"Overall Security Score: {security_results['overall_score']} (Grade: {security_results['overall_grade']})\n\n"

        # Add SPF, DKIM, DMARC details
        for protocol in ['SPF', 'DKIM', 'DMARC']:
            result = security_results[protocol.lower()]
            body += f"{protocol} Analysis:\n"
            body += f"  Score: {result['score']} (Grade: {result['grade']})\n"
            if result.get('issues'):
                body += f"  Issues: {', '.join(result['issues'])}\n"
            if result.get('recommendations'):
                body += f"  Recommendations: {', '.join(result['recommendations'])}\n"
            body += "\n"

        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, 587)
        server.starttls()
        server.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ACCOUNT, sender_email, msg.as_string())
        server.quit()

        print(f"Security alert sent to {sender_email}")
    except Exception as e:
        print("Error sending security alert:", e)

def process_email(msg_data):
    """Process a single email message."""
    try:
        email_msg = email.message_from_bytes(msg_data[1], policy=policy.default)
        
        # Get the original sender's email from the forwarded message
        original_sender = None
        for part in email_msg.walk():
            if part.get_content_type() == "text/plain":
                content = part.get_payload(decode=True).decode()
                # Look for "From:" in the forwarded message
                match = re.search(r"From:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content)
                if match:
                    original_sender = match.group(1)
                    break

        if not original_sender:
            print("Could not find original sender email in forwarded message")
            return

        # Initialize security analyzer
        analyzer = EmailSecurityAnalyzer()
        security_results = analyzer.comprehensive_email_security_analysis(original_sender)

        # Process attachments
        attachment_results = {}
        for part in email_msg.iter_attachments():
            filename = part.get_filename()
            if filename:
                print(f"Processing attachment: {filename}")
                if handle_attachment(part, filename, original_sender):
                    attachment_results[filename] = {
                        "status": "Safe",
                        "details": "No threats detected"
                    }
                else:
                    attachment_results[filename] = {
                        "status": "Suspicious",
                        "details": "Potential security threat detected"
                    }

        # Send analysis report
        sender_email = email.utils.parseaddr(email_msg["From"])[1]
        send_analysis_report(sender_email, security_results, attachment_results)

        # Send security alert if the email was not secure
        if security_results['overall_grade'] in ['D', 'F']:
            send_security_alert(original_sender, security_results)

    except Exception as e:
        print(f"Error processing email: {e}")

def monitor_inbox():
    """Monitor inbox for new emails and process them."""
    print("Starting Email Security Monitor...")
    
    while True:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
            mail.select("inbox")

            result, data = mail.search(None, "UNSEEN")
            mail_ids = data[0].split()

            if mail_ids:
                for mail_id in mail_ids:
                    result, msg_data = mail.fetch(mail_id, "(RFC822)")
                    process_email(msg_data[0])
                    mail.store(mail_id, "+FLAGS", "\\Seen")

            mail.logout()
            time.sleep(CHECK_INTERVAL)

        except Exception as e:
            print(f"Error monitoring inbox: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_inbox()