 Vulnerability Scanner – Web Interface

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, multi‑threaded vulnerability scanner with a clean web UI. It performs port scanning, checks for missing security headers, detects server information, and identifies common misconfigurations – all accessible through a browser‑based interface.



 Features

Web Dashboard** – Start scans and view results directly from your browser.
Multi‑threaded Port Scanner** – Quickly scans common ports (21, 22, 23, 25, 80, 443, 3306, 3389, 8080) with configurable thread count.
Web Vulnerability Checks** – Detects missing security headers (HSTS, CSP, X‑Frame‑Options, etc.), server fingerprinting, outdated software versions, and directory listing.
JSON Result Output** – Returns structured scan results via API, with a summary of findings and risk breakdown.
Standalone CLI Mode** – The core scanner can also run as a command‑line tool for quick scans
