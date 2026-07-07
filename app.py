#!/usr/bin/env python3
"""
Vulnerability Scanner - Web Interface (FINAL FIXED VERSION)
"""

from flask import Flask, render_template, request, jsonify
import traceback
import sys

app = Flask(__name__)

# Import the scanner with error handling
try:
    from scanner_core import run_full_scan
    print("✅ Scanner imported successfully!")
except Exception as e:
    print(f"❌ ERROR importing scanner: {e}")
    print("Make sure scanner_core.py is in the same folder.")
    sys.exit(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        # Get JSON data from request
        data = request.get_json()
        print(f"📥 Received data: {data}")
        
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400
            
        target = data.get('target', '').strip()  # ← FIXED: no space!
        print(f"🎯 Target: '{target}'")
        
        if not target:
            return jsonify({'error': 'Please enter a valid target'}), 400
        
        # Run the scan
        print(f"🔍 Scanning: {target}")
        results = run_full_scan(target)
        print(f"✅ Scan complete! Found {len(results.get('open_ports', []))} open ports.")
        
        # Return JSON results
        return jsonify(results)
        
    except Exception as e:
        error_msg = f"Error during scan: {str(e)}"
        print(f"❌ {error_msg}")
        print(traceback.format_exc())
        # ALWAYS return JSON, never HTML
        return jsonify({
            'error': error_msg,
            'open_ports': [],
            'vulnerabilities': [{
                'type': 'Scanner Error',
                'detail': error_msg,
                'risk': 'High'
            }]
        }), 500

# Add a test route to verify the server is working
@app.route('/test')
def test():
    return jsonify({'status': 'Server is running!', 'message': 'Flask is working correctly.'})

if __name__ == '__main__':
    print("="*60)
    print("🌐 Vulnerability Scanner Web Interface")
    print("="*60)
    print("👉 Open http://127.0.0.1:5000 in your browser")
    print("👉 Test endpoint: http://127.0.0.1:5000/test")
    print("="*60)
    app.run(debug=True, host='127.0.0.1', port=5000)