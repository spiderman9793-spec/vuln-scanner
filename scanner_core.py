#!/usr/bin/env python3
"""
Scanner Core Logic - FINAL FIXED VERSION
"""
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 2
THREADS = 100
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]

def scan_ports(host, ports=COMMON_PORTS):
    """Scan ports and return list of open ports."""
    open_ports = []
    
    def scan_single(port):
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

    try:
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            futures = [ex.submit(scan_single, p) for p in ports]
            for f in as_completed(futures):
                res = f.result()
                if res:
                    open_ports.append(res)
    except Exception as e:
        print(f"⚠️ Port scan error: {e}")
    
    return sorted(open_ports)

def check_web_vulnerabilities(url):
    """Check a web URL for missing headers and server info."""
    findings = []
    try:
        print(f"🌐 Checking: {url}")
        resp = requests.get(url, timeout=5, allow_redirects=False)
        headers = resp.headers

        security_headers = {
            'Strict-Transport-Security': 'HSTS missing (downgrade attacks)',
            'Content-Security-Policy': 'CSP missing (XSS risk)',
            'X-Content-Type-Options': 'MIME sniffing missing',
            'X-Frame-Options': 'Clickjacking missing'
        }
        for hdr, msg in security_headers.items():
            if hdr not in headers:
                findings.append({'type': 'Missing Header', 'detail': msg, 'risk': 'Medium'})

        server = headers.get('Server', '')
        if server:
            findings.append({'type': 'Server Info', 'detail': f'Server: {server}', 'risk': 'Info'})
            if 'Apache/2.2' in server or 'Apache/2.4.7' in server:
                findings.append({'type': 'Outdated Software', 'detail': f'{server} is outdated', 'risk': 'High'})

        # Check directory listing
        try:
            dir_resp = requests.get(url.rstrip('/') + '/', timeout=5)
            if 'Index of /' in dir_resp.text:
                findings.append({'type': 'Weak Config', 'detail': 'Directory listing enabled', 'risk': 'Medium'})
        except:
            pass

    except requests.exceptions.ConnectionError:
        findings.append({'type': 'Error', 'detail': f'Cannot connect to {url}', 'risk': 'Info'})
    except requests.exceptions.Timeout:
        findings.append({'type': 'Error', 'detail': f'Timeout connecting to {url}', 'risk': 'Info'})
    except Exception as e:
        findings.append({'type': 'Error', 'detail': f'Web scan error: {str(e)}', 'risk': 'Info'})
        print(f"⚠️ Web scan error: {e}")
    
    return findings

def run_full_scan(target):
    """Runs the full scan and returns structured results."""
    print(f"🚀 Starting scan for: {target}")
    
    result = {
        'target': target,
        'open_ports': [],
        'web_url': None,
        'vulnerabilities': []
    }
    
    try:
        # 1. Port scan
        open_ports = scan_ports(target, COMMON_PORTS)
        result['open_ports'] = open_ports
        print(f"📡 Open ports found: {open_ports}")
        
        # 2. Web scan if web ports are open
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8000]]
        if web_ports:
            port = web_ports[0]
            protocol = "https" if port == 443 else "http"
            if port in [80, 443]:
                web_url = f"{protocol}://{target}"
            else:
                web_url = f"{protocol}://{target}:{port}"
            result['web_url'] = web_url
            result['vulnerabilities'] = check_web_vulnerabilities(web_url)
        else:
            print("ℹ️ No web ports found, skipping web scan.")
            
    except Exception as e:
        print(f"❌ Critical error in run_full_scan: {e}")
        result['vulnerabilities'].append({
            'type': 'Scanner Error',
            'detail': f'Scan failed: {str(e)}',
            'risk': 'High'
        })
    
    print(f"✅ Scan complete.")
    return result