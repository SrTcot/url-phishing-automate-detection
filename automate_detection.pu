#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple URL Phishing Detector – Improved Version
Author: <SrTCOT>
"""

import argparse
import datetime
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

import requests


# -------------------------------------------------------------
# Configuration / Constants
# -------------------------------------------------------------
FAKE_BRANDS = [
    "paypal", "facebook", "google", "microsoft",
    "bank", "apple", "amazon"
]

PRIVATE_IP_PREFIXES = ("10.", "172.", "192.168.")

SSL_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def extract_domain(url: str) -> str:
    url = url.strip().lower()
    url = re.sub(r"^https?://", "", url)
    url = url.split("/")[0]
    domain = url.split(":")[0]
    return domain


def fetch_ssl_expiry(domain: str, timeout: int = 5) -> Optional[str]:
    """Return SSL certificate expiry date (notAfter) or None."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return cert.get("notAfter")
    except Exception:
        return None


def is_private_ip(ip: str) -> bool:
    return ip.startswith(PRIVATE_IP_PREFIXES)


def classify_http_status(status: int) -> str:
    if status >= 500:
        return "Server error (5xx)"
    if status >= 400:
        return "Client error (4xx)"
    return ""


# -------------------------------------------------------------
# Data Structures
# -------------------------------------------------------------
@dataclass
class URLAnalysisResult:
    url: str
    domain: str
    issues: List[str] = field(default_factory=list)
    resolved_ip: Optional[str] = None
    ssl_expiry: Optional[str] = None
    final_http_status: Optional[int] = None
    final_redirect_url: Optional[str] = None


# -------------------------------------------------------------
# Main Analysis Logic
# -------------------------------------------------------------
def analyze_url(url: str) -> URLAnalysisResult:
    result = URLAnalysisResult(url=url, domain=extract_domain(url))

    print(f"\n[INFO] Analyzing: {url}")
    print(f"[INFO] Domain extracted: {result.domain}")

    # ---------------------------------------------------------
    # Basic heuristic checks on URL structure
    # ---------------------------------------------------------
    if len(url) > 75:
        result.issues.append("URL length exceeds recommended threshold")

    if url.count("-") > 3:
        result.issues.append("Excessive hyphens detected")

    if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url):
        result.issues.append("URL contains a raw IPv4 address")

    for brand in FAKE_BRANDS:
        if brand in url.lower() and "-" in url:
            result.issues.append(f"Suspicious brand impersonation pattern: {brand}")

    # ---------------------------------------------------------
    # DNS resolution
    # ---------------------------------------------------------
    try:
        ip = socket.gethostbyname(result.domain)
        result.resolved_ip = ip
        print(f"[INFO] DNS Resolved IP: {ip}")

        if is_private_ip(ip):
            result.issues.append("Domain resolves to a private IP address")

    except socket.gaierror:
        result.issues.append("DNS resolution failed")
    except Exception as e:
        result.issues.append(f"DNS resolution error: {str(e)}")

    # ---------------------------------------------------------
    # SSL certificate analysis
    # ---------------------------------------------------------
    ssl_exp = fetch_ssl_expiry(result.domain)
    result.ssl_expiry = ssl_exp

    if ssl_exp:
        print(f"[INFO] SSL certificate expires on: {ssl_exp}")
        try:
            exp_dt = datetime.strptime(ssl_exp, SSL_DATE_FORMAT).replace(tzinfo=timezone.utc)
            days_left = (exp_dt - datetime.now(timezone.utc)).days

            if days_left < 0:
                result.issues.append("SSL certificate expired")
            elif days_left < 30:
                result.issues.append("SSL certificate due to expire within 30 days")

        except ValueError:
            result.issues.append("Failed to parse SSL expiry date")
    else:
        result.issues.append("SSL certificate missing or unavailable")

    # ---------------------------------------------------------
    # HTTP HEAD request
    # ---------------------------------------------------------
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        result.final_http_status = response.status_code
        result.final_redirect_url = response.url

        error_label = classify_http_status(response.status_code)
        if error_label:
            result.issues.append(f"HTTP error ({response.status_code}) – {error_label}")

        if any(k in response.url.lower() for k in ("login", "verify")):
            result.issues.append("Redirect leads to a suspicious login/verification page")

    except requests.exceptions.SSLError:
        result.issues.append("SSL/TLS handshake error")
    except requests.exceptions.RequestException as e:
        result.issues.append(f"HTTP request error: {str(e)}")

    return result


# -------------------------------------------------------------
# Printing / Output
# -------------------------------------------------------------
def display_result(result: URLAnalysisResult):
    print("\n==================== RESULT ====================")
    print(f"URL: {result.url}")
    print(f"Domain: {result.domain}")

    if result.resolved_ip:
        print(f"Resolved IP: {result.resolved_ip}")

    if result.ssl_expiry:
        print(f"SSL Expiry: {result.ssl_expiry}")

    if result.final_http_status:
        print(f"HTTP Status: {result.final_http_status}")
        print(f"Final URL: {result.final_redirect_url}")

    print("\n--- Potential Issues ---")
    if result.issues:
        for issue in result.issues:
            print(f" - {issue}")
    else:
        print("No suspicious indicators detected")
    print("================================================\n")


# -------------------------------------------------------------
# CLI Entry Point
# -------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Improved URL Phishing Detector"
    )
    parser.add_argument("url", help="URL to analyze (e.g., https://example.com)")
    args = parser.parse_args()

    result = analyze_url(args.url)
    display_result(result)


if __name__ == "__main__":
    main()
