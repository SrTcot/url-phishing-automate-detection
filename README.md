# 🔍 Advanced URL Phishing Detector  
A lightweight Python tool designed to perform heuristic, DNS, SSL, and HTTP-level checks to identify potentially malicious or suspicious URLs.

This utility is ideal for cybersecurity analysts, threat hunters, SOC teams, developers, and anyone who needs a quick way to pre-screen URLs before deeper analysis.



## 🚀 Features

### **1. URL Heuristic Analysis**
- Detects overly-long URLs  
- Flags excessive hyphens  
- Identifies raw IP-based URLs  
- Detects suspicious impersonation patterns (PayPal, Google, Microsoft, banks, etc.)

### **2. DNS Validation**
- Extracts and resolves domain  
- Warns if DNS resolution fails  
- Detects private or internal IP mappings (possible phishing or misconfiguration)

### **3. SSL Certificate Inspection**
- Fetches the certificate using TLS handshake  
- Extracts `notAfter` expiry date  
- Detects:
  - Expired certificates  
  - Soon-to-expire certificates (<30 days)  
  - Missing certificates / handshake failures

### **4. HTTP Security Behavior**
- Performs HEAD request  
- Follows redirects  
- Flags suspicious redirect targets (e.g., `/login`, `/verify`)  
- Detects HTTP 4xx/5xx error responses  



## 📦 Installation

Clone the repository:

bash
git clone https://github.com/SrTcot/url-phishing-automate-detection.git
cd url-phishing-automate-detection

Install dependencies:

pip install -r requirements.txt

> Required libraries:

requests





🛠 # Usage

Run the tool from the terminal:

python3 phishing_checker.py https://example.com

## Example output:

[INFO] Analyzing: https://example.com
[INFO] Domain extracted: example.com
[INFO] DNS Resolved IP: 93.184.216.34
[INFO] SSL certificate expires on: Jan 10 12:00:00 2026 GMT

==================== RESULT ====================
URL: https://example.com
Domain: example.com
Resolved IP: 93.184.216.34
SSL Expiry: Jan 10 12:00:00 2026 GMT
HTTP Status: 200
Final URL: https://example.com/

--- Potential Issues ---
No suspicious indicators detected
================================================




🧩 # Code Structure

/
├── phishing_checker.py   # Main script containing analysis logic
├── README.md             # Documentation
└── requirements.txt      # Python dependencies




⚙️ # Internals & Architecture

Core Components

Component	Description

extract_domain()	Normalizes and extracts domain names from URLs
fetch_ssl_expiry()	Performs TLS handshake & retrieves certificate metadata
analyze_url()	Runs all heuristic, DNS, SSL, and HTTP checks
URLAnalysisResult	Dataclass storing structured scan results
display_result()	Pretty-print scan results




🛡 # How Detection Works

This script uses multi-layered URL analysis, including:

1. String-based heuristic filtering


2. DNS-level resolution validation


3. SSL certificate credibility checks


4. HTTP redirect chain inspection



This combination allows detection of:

Fraudulent login redirects

Typosquatting domains

Expired/missing TLS certificates

Suspicious hosting IPs

Malicious domain impersonations



📘 # Example: Detecting a Suspicious URL

Command:

python3 phishing_checker.py https://paypal-security-center-login-verification.com

Possible output:

- Suspicious brand impersonation pattern: paypal
 - Excessive hyphens detected
 - Redirect leads to a suspicious login/verification page
 - SSL certificate due to expire within 30 days


🧪 # Testing

Run static checks:

python3 phishing_checker.py https://expired.badssl.com
python3 phishing_checker.py http://example-login-verify.site
python3 phishing_checker.py http://192.168.1.55


📄 # License

This project is released under the MIT License.


🤝 # Contributing

Pull requests are welcome.
Feel free to open issues for:

Feature requests

Bug reports

Improvements

Detection logic proposals


⭐ # Support

If you find the tool useful, consider giving the repo a star ⭐ on GitHub!
