import smtplib
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse
import traceback

app = Flask(__name__)
CORS(app)

WHOIS_API_KEY = 'at_A1T36TbumbghrdLPrFcGMXMrBfNTn'
SENDER_EMAIL = 'saikarthan2@gmail.com'
SENDER_PASSWORD = 'moxn uvva yiva cfre'
ADMIN_EMAIL = 'anonymousvoice4business@gmail.com'

def get_whois_info(domain):
    whois_url = (
        f'https://www.whoisxmlapi.com/whoisserver/WhoisService?'
        f'apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON'
    )
    try:
        resp = requests.get(whois_url, timeout=5)
        data = resp.json()
        record = data.get('WhoisRecord', {})
        registrar = record.get('registrarName', 'Unknown')
        creation = record.get('createdDate', 'Unknown')
        expiry = record.get('expiresDate', 'Unknown')
        registrant = record.get('registrant', {}).get('name', 'Unknown')
        return (f"Registrar: {registrar}\n"
                f"Creation Date: {creation}\n"
                f"Expiration Date: {expiry}\n"
                f"Registrant Name: {registrant}")
    except Exception as e:
        return f"Unable to fetch WHOIS info: {str(e)}"

def get_wayback_urls(domain):
    # For domains, fetch wayback for base domain, not 'www.' or 'https' prefix
    base_domain = domain.replace("www.", "")
    try:
        resp = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url={base_domain}&output=json&fl=original&limit=5"
        )
        if resp.status_code == 200:
            data = resp.json()
            urls = [row[0] for row in data[1:]] if len(data) > 1 else []
            if urls:
                return "Recent URLs from Wayback Machine:\n" + "\n".join(urls)
            else:
                return "No snapshots found in Wayback Machine."
        else:
            return "Error fetching Wayback Machine data."
    except Exception as e:
        return f"Unable to fetch Wayback Machine info: {str(e)}"

def send_email(subject, body, recipient):
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("Report email sent successfully")
        return True
    except Exception as ex:
        print("Email sending failed:", ex)
        traceback.print_exc()
        return False

@app.route('/report', methods=['POST'])
def report_url():
    try:
        data = request.get_json(force=True)
        url = data.get('url')
        print("Received report for:", url)
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        domain = urlparse(url).hostname
        whois_info = get_whois_info(domain)
        wayback_info = get_wayback_urls(domain)
        email_body = f"""Malware / phishing URL detected:
{url}

WHOIS information:
{whois_info}

{wayback_info}

Please review and ban this URL as soon as possible.
"""
        sent = send_email("Malware URL Report", email_body, ADMIN_EMAIL)
        if sent:
            return jsonify({"result": "Report sent successfully"})
        else:
            return jsonify({"error": "Failed to send report email"}), 500
    except Exception as e:
        print(f"Error processing report: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
