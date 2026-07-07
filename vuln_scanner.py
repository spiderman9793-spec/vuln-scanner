#!/usr/bin/env python3
"""
Vulnerability Scanner Mini-Project (Threaded Edition)
Author: Your Name
"""

import socket
import requests
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- Configuration ----------
TARGET_HOST = "127.0.0.1"           # <-- CHANGE THIS TO YOUR LOCALHOST
TARGET_PORT = 8080                  # <-- WE WILL SCAN THIS SPECIFIC PORT
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]  # 8080 is in here!
TIMEOUT = 2
THREADS = 100

# ---------- Port Scanner (Multi-Threaded) ----------
def scan_ports(host, ports):
    open_ports = []
    def scan_single_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            if sock.connect_ex((host, port)) == 0:
                sock.close()
                return port
            sock.close()
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_single_port, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

# ---------- Web Vulnerability Checks ----------
def check_web_vulnerabilities(url):
    findings = []
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        headers = resp.headers

        security_headers = {
            'Strict-Transport-Security': 'HSTS missing (risk: downgrade attacks)',
            'Content-Security-Policy': 'CSP missing (risk: XSS)',
            'X-Content-Type-Options': 'MIME sniffing protection missing',
            'X-Frame-Options': 'Clickjacking protection missing'
        }
        for hdr, msg in security_headers.items():
            if hdr not in headers:
                findings.append({'type': 'Missing Header', 'detail': msg, 'risk': 'Medium'})

        server = headers.get('Server', '')
        if server:
            findings.append({'type': 'Server Info', 'detail': f'Server: {server}', 'risk': 'Info'})
            if 'Apache/2.2' in server:
                findings.append({'type': 'Outdated Software', 'detail': 'Apache 2.2 is EOL', 'risk': 'High'})
            elif 'nginx/1.12' in server:
                findings.append({'type': 'Outdated Software', 'detail': 'nginx 1.12 vulnerable', 'risk': 'Medium'})

        test_dir = url.rstrip('/') + '/'
        try:
            dir_resp = requests.get(test_dir, timeout=5)
            if 'Index of /' in dir_resp.text:
                findings.append({'type': 'Weak Config', 'detail': 'Directory listing enabled', 'risk': 'Medium'})
        except:
            pass

    except Exception as e:
        findings.append({'type': 'Error', 'detail': f'Web scan failed: {str(e)}', 'risk': 'Info'})
    return findings

# ---------- Report Generator ----------
def generate_report(host, open_ports, web_findings):
    report = {
        'scan_time': datetime.now().isoformat(),
        'target': host,
        'open_ports': open_ports,
        'web_vulnerabilities': web_findings,
        'summary': {
            'total_open_ports': len(open_ports),
            'total_web_issues': len(web_findings),
            'risk_breakdown': {}
        }
    }
    risks = {}
    for item in web_findings:
        risk = item.get('risk', 'Unknown')
        risks[risk] = risks.get(risk, 0) + 1
    report['summary']['risk_breakdown'] = risks

    print("\n" + "="*60)
    print(f" VULNERABILITY SCAN REPORT for {host}")
    print("="*60)
    print(f"Scan started: {report['scan_time']}")
    print("\n[+] Open Ports:")
    if open_ports:
        for p in open_ports:
            print(f"    - {p}/tcp")
    else:
        print("    None found.")

    print("\n[+] Web Vulnerabilities:")
    if web_findings:
        for item in web_findings:
            print(f"    [{item['risk']}] {item['type']}: {item['detail']}")
    else:
        print("    No web issues detected.")

    print("\n[+] Summary:")
    print(f"    Open Ports          : {report['summary']['total_open_ports']}")
    print(f"    Web Issues          : {report['summary']['total_web_issues']}")
    print(f"    Risk Breakdown      : {report['summary']['risk_breakdown']}")
    print("="*60 + "\n")

    with open(f"scan_report_{host}.json", "w") as f:
        json.dump(report, f, indent=4)
    print(f"Detailed JSON report saved as scan_report_{host}.json")

# ---------- Main Execution ----------
if __name__ == "__main__":
    print(f"🚀 Starting vulnerability scan on {TARGET_HOST} (Using {THREADS} threads)")

    open_ports = scan_ports(TARGET_HOST, COMMON_PORTS)

    web_findings = []
    if TARGET_PORT in open_ports or 443 in open_ports:
        protocol = "https" if 443 in open_ports else "http"
        url = f"{protocol}://{TARGET_HOST}:{TARGET_PORT}" if TARGET_PORT not in [80, 443] else f"{protocol}://{TARGET_HOST}"
        print(f"🔍 Scanning web application at {url}")
        web_findings = check_web_vulnerabilities(url)

    generate_report(TARGET_HOST, open_ports, web_findings)