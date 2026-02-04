from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import zap
import nmap_scanner as nmap
import database
import report
import os
import owasp_mapper
import nuclei_scan
from concurrent.futures import ThreadPoolExecutor

# Configure Flask
app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app) # Enable CORS for all routes

# Initialize DB on start
database.init_db()

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "ShieldByte Backend"})

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({"error": "URL is required"}), 400
        
    # Standardize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    print(f"Received scan request for: {target_url}")
    scan_mode = data.get('scanMode', 'fast')
    scan_options = data.get('scanOptions', [])
    
    # Use ThreadPoolExecutor for Parallel Scanning (ZAP RE-ENABLED)
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit ZAP, Nuclei and Nmap in parallel
        future_zap = executor.submit(zap.run_zap_scan, target_url, scan_options)
        future_nmap = executor.submit(nmap.run_scan, target_url, scan_mode)
        future_nuclei = executor.submit(nuclei_scan.run_nuclei_scan, target_url)

        # Wait for results
        zap_results = future_zap.result()
        nmap_results = future_nmap.result()
        nuclei_raw = future_nuclei.result()

    # 3. Determine Risk Level & Augment with OWASP Info
    risk_level = "Low"
    processed_vulns = []
    
    # Process ZAP Results
    for vuln in zap_results:
        # Determine Risk
        if vuln['severity'] == "Critical":
            risk_level = "Critical"
        elif vuln['severity'] == "High" and risk_level != "Critical":
            risk_level = "High"
             
        # Map to OWASP
        owasp_code, owasp_name = owasp_mapper.get_owasp_category(vuln['type'])
        
        processed_vulns.append({
            "type": vuln['type'],
            "severity": vuln['severity'].upper(),
            "location": vuln['location'],
            "owasp_code": owasp_code,
            "owasp_name": owasp_name,
            "description": vuln.get('description', 'No description'),
            "source": "ZAP"
        })

    # Process Nuclei Results (Map Nuclei's unique format to our standard)
    for res in nuclei_raw:
        if not isinstance(res, dict):
            continue
        info = res.get('info', {})
        vuln_type = info.get('name', 'Nuclei Alert')
        severity = info.get('severity', 'low').upper()
        
        # Determine Risk
        if severity == "CRITICAL":
            risk_level = "Critical"
        elif severity == "HIGH" and risk_level != "Critical":
            risk_level = "High"

        owasp_code, owasp_name = owasp_mapper.get_owasp_category(vuln_type)
        
        processed_vulns.append({
            "type": vuln_type,
            "severity": severity,
            "location": res.get('matched-at', target_url),
            "owasp_code": owasp_code,
            "owasp_name": owasp_name,
            "description": info.get('description', 'No description'),
            "source": "Nuclei"
        })

    # Update logic if Nmap found many ports
    if risk_level not in ["Critical", "High"] and len(nmap_results) > 5:
        risk_level = "Medium"

    # Sort by OWASP Code (A01 -> A10 -> OTH)
    processed_vulns.sort(key=lambda x: x['owasp_code'])

    # 4. Prepare Final Data
    scan_id = f"scan_{database.get_next_scan_id()}"
    
    scan_data = {
        "scan_id": scan_id,
        "target": target_url,
        "riskLevel": risk_level,
        "vulnerabilities": processed_vulns,
        "nmap": nmap_results
    }
    
    # 5. Save to Database
    db_id = database.save_scan(scan_data)
    scan_data['id'] = db_id
    
    return jsonify(scan_data)

if __name__ == '__main__':
    print("🚀 ShieldByte Backend is running...")
    print("👉 Local: http://127.0.0.1:5000")
    print("👉 Network: http://(your-ip-address):5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
