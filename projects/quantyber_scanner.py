#!/usr/bin/env python3
"""
Quantyber Scanner v1.0
Author: Mohammed Sharuk Khan
GitHub: mohammedsharukkhan8-png
Description: Basic vulnerability scanner — ports, headers, SQL injection
"""

import socket
import requests
from datetime import datetime

def scan_ports(host, ports=[21,22,23,25,53,80,443,3306,8080,8888]):
    print(f"\n{'='*55}")
    print(f"🔍 PORT SCAN: {host}")
    print('='*55)
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            services = {
                21: "FTP", 22: "SSH", 23: "Telnet",
                25: "SMTP", 53: "DNS", 80: "HTTP",
                443: "HTTPS", 3306: "MySQL",
                8080: "HTTP-Alt", 8888: "Jupyter"
            }
            service = services.get(port, "Unknown")
            risk = "🔴 HIGH" if port in [21,23,3306] else "🟡 MEDIUM" if port in [22,25,8080,8888] else "🟢 LOW"
            print(f"Port {port:5d} ({service:10s}) → OPEN {risk}")
            open_ports.append({"port": port, "service": service})
        sock.close()
    if not open_ports:
        print("No common ports open ✅")
    return open_ports

def analyze_headers(url):
    print(f"\n{'='*55}")
    print(f"🔍 SECURITY HEADERS: {url}")
    print('='*55)
    security_headers = {
        "Strict-Transport-Security": "🔴 Missing HSTS — HTTP downgrade possible",
        "X-Frame-Options":           "🔴 Missing — Clickjacking possible",
        "X-Content-Type-Options":    "🟡 Missing — MIME sniffing possible",
        "Content-Security-Policy":   "🔴 Missing — XSS attacks possible",
        "Referrer-Policy":           "🟡 Missing — Info leakage possible",
        "X-XSS-Protection":          "🟡 Missing — XSS protection disabled"
    }
    findings = []
    try:
        response = requests.get(url, timeout=5)
        print(f"Status: {response.status_code}\n")
        for header, warning in security_headers.items():
            if header in response.headers:
                print(f"✅ {header}: {response.headers[header][:50]}")
            else:
                print(f"❌ {warning}")
                findings.append(warning)
    except Exception as e:
        print(f"Error: {e}")
    return findings

def test_sql_injection(url):
    print(f"\n{'='*55}")
    print(f"🔍 SQL INJECTION TEST: {url}")
    print('='*55)
    payloads = [
        "' OR '1'='1", "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--", "admin'--"
    ]
    error_signatures = [
        "mysql", "sqlite", "postgresql",
        "ORA-", "syntax error", "SQLSTATE",
        "microsoft", "odbc", "jdbc"
    ]
    vulnerabilities = []
    for payload in payloads:
        try:
            response = requests.get(f"{url}?id={payload}", timeout=5)
            content = response.text.lower()
            for sig in error_signatures:
                if sig in content:
                    print(f"❌ VULNERABLE! Payload: {payload[:30]}")
                    print(f"   Signature: '{sig}'")
                    vulnerabilities.append(payload)
                    break
            else:
                print(f"✅ Safe against: {payload[:30]}")
        except Exception as e:
            print(f"⚠️  Error: {e}")
    return vulnerabilities

def generate_report(target_host, target_url):
    print(f"\n{'='*55}")
    print(f"🛡️  VULNERABILITY ASSESSMENT REPORT")
    print(f"{'='*55}")
    print(f"Target Host: {target_host}")
    print(f"Target URL:  {target_url}")
    print(f"Scan Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scanner:     Quantyber Scanner v1.0 — Sharuk")

    open_ports   = scan_ports(target_host)
    header_risks = analyze_headers(target_url)
    sqli_risks   = test_sql_injection(target_url)

    total_issues = len(open_ports) + len(header_risks) + len(sqli_risks)
    risk_level = (
        "🟢 LOW" if total_issues == 0 else
        "🟡 MEDIUM" if total_issues <= 3 else
        "🔴 HIGH" if total_issues <= 6 else
        "🚨 CRITICAL"
    )

    print(f"\n{'='*55}")
    print(f"📊 EXECUTIVE SUMMARY")
    print(f"{'='*55}")
    print(f"Open Ports Found:     {len(open_ports)}")
    print(f"Header Issues:        {len(header_risks)}")
    print(f"SQL Injection Points: {len(sqli_risks)}")
    print(f"Total Issues:         {total_issues}")
    print(f"Overall Risk Level:   {risk_level}")

    print(f"\n{'='*55}")
    print(f"💡 RECOMMENDATIONS")
    print(f"{'='*55}")
    if open_ports:
        print("• Close unnecessary open ports")
        print("• Restrict database ports to localhost only")
    if header_risks:
        print("• Add missing security headers")
        print("• Implement Content Security Policy")
        print("• Enable HSTS for HTTPS enforcement")
    if sqli_risks:
        print("• Use parameterized queries always")
        print("• Sanitize all user inputs")
        print("• Implement Web Application Firewall")

    print(f"\n{'='*55}")
    print(f"✅ Report Complete")
    print(f"{'='*55}")

if __name__ == "__main__":
    generate_report("127.0.0.1", "http://127.0.0.1:9999")
