from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import zap
import nmap_scanner as nmap
import database
import report
import os
import owasp_mapper
import nuclei_scan
import scanner_manager
import json
import re
import html
from concurrent.futures import ThreadPoolExecutor
from gotrue.errors import AuthApiError

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
    
    # 1. Cleanup old data (> 24h)
    database.cleanup_stale_data()
    
    # 2. Check Cache (Is there a completed scan for this URL in last 24h?)
    recent_scan = database.get_recent_scan(target_url)
    if recent_scan:
        print(f"Reusing recent scan results for: {target_url} (ID: {recent_scan['id']})")
        return jsonify({
            "message": "Results retrieved from cache",
            "scan_id": recent_scan['id'],
            "target": target_url,
            "reused": True
        })
    
    # 3. Start new scan if no cache found
    scan_db_id = scanner_manager.start_background_scan(target_url, scan_options, scan_mode)
    
    return jsonify({
        "message": "Scan initiated",
        "scan_id": scan_db_id,
        "target": target_url,
        "reused": False
    })

@app.route('/api/scan/status/<int:scan_id>', methods=['GET'])
def get_status(scan_id):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
        
    # Process vulnerabilities - Supabase already returns these as lists
    zap_raw = scan.get('zap_results') or []
    if not isinstance(zap_raw, list):
        zap_raw = []
        
    processed_vulns = []
    
    for vuln in zap_raw:
        owasp_code, owasp_name = owasp_mapper.get_owasp_category(vuln['type'])
        processed_vulns.append({
            **vuln,
            "owasp_code": owasp_code,
            "owasp_name": owasp_name
        })
        
    # Sort by OWASP Code
    processed_vulns.sort(key=lambda x: x['owasp_code'])
        
    return jsonify({
        "scan_id": scan.get('id'),
        "status": scan.get('status', 'Running'),
        "progress": scan.get('progress', 0),
        "is_paused": bool(scan.get('is_paused', 0)),
        "target": scan.get('url', ''),
        "riskLevel": scan.get('risk_level', 'Low'),
        "vulnerabilities": processed_vulns,
        "nmap": scan.get('nmap_results') or []
    })

@app.route('/api/scan/control/<int:scan_id>/<action>', methods=['POST'])
def control_scan(scan_id, action):
    result = scanner_manager.control_scan(scan_id, action)
    return jsonify(result)

@app.route('/api/scan/download/<int:scan_id>/<file_format>', methods=['GET'])
def download_results(scan_id, file_format):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    # Process vulnerabilities for the report - Supabase returns lists
    zap_raw = scan.get('zap_results') or []
    vulnerabilities = []
    for vuln in zap_raw:
        owasp_code, owasp_name = owasp_mapper.get_owasp_category(vuln['type'])
        vulnerabilities.append({**vuln, "owasp_code": owasp_code, "owasp_name": owasp_name})
    
    report_data = {
        "scan_id": scan.get('id'),
        "url": scan.get('url'),
        "timestamp": scan.get('timestamp'),
        "risk_level": scan.get('risk_level'),
        "vulnerabilities": vulnerabilities,
        "nmap": scan.get('nmap_results') or []
    }

    if file_format == 'json':
        from flask import Response
        json_content = json.dumps(report_data, indent=4)
        return Response(
            json_content,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment;filename=shieldbyte_scan_{scan_id}.json'}
        )
    
    elif file_format == 'pdf':
        # Simple PDF generation using fpdf if available, or just a formatted text response for now
        # For a professional project, we'd use reportlab or fpdf
        try:
            from fpdf import FPDF
            
            class PDF(FPDF):
                def header(self):
                    self.set_font('Arial', 'B', 15)
                    self.cell(0, 10, 'ShieldByte Security Scan Report', 0, 1, 'C')
                    self.ln(5)

            pdf = PDF()
            pdf.add_page()
            pdf.set_font('Arial', '', 12)
            
            pdf.cell(0, 10, f"Target: {report_data['url']}", 0, 1)
            pdf.cell(0, 10, f"Date: {report_data['timestamp']}", 0, 1)
            pdf.cell(0, 10, f"Risk Level: {report_data['risk_level']}", 0, 1)
            pdf.ln(10)
            
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Vulnerabilities', 0, 1)
            pdf.set_font('Arial', '', 10)
            
            for v in vulnerabilities:
                pdf.multi_cell(0, 7, f"[{v['severity']}] {v['owasp_code']}: {v['owasp_name']}\nType: {v['type']}\nSource: {v['source']}\n", 1)
                pdf.ln(2)
            
            pdf_output = pdf.output(dest='S').encode('latin-1')
            return Response(
                pdf_output,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment;filename=shieldbyte_scan_{scan_id}.pdf'}
            )
        except ImportError:
            return jsonify({"error": "PDF generation library (fpdf) not installed. Please install it or use JSON download."}), 500
        except Exception as e:
            return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email', '').strip()
    password = data.get('password', '')
    name = html.escape(data.get('name', '').strip()) # XSS Protection
    username = html.escape(data.get('username', '').strip()) # XSS Protection
    
    # 1. Validation Logic
    if not email or not password or not name or not username:
        return jsonify({"error": "All fields are required"}), 400
    
    # Email Regex
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400
        
    # Username Regex (Alphanumeric only)
    if not re.match(r"^[a-zA-Z0-9_\-]+$", username):
        return jsonify({"error": "Username can only contain letters, numbers, underscores, and hyphens"}), 400
        
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400
        
    try:
        # 2. Supabase Auth Sign Up
        res = database.supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {
                    "full_name": name,
                    "username": username
                }
            }
        })
        
        # 3. Save to Public Users Table (Syncing)
        # Note: This might fail if the user didn't create the table yet
        try:
            database.supabase.table("users").insert({
                "id": res.user.id,
                "full_name": name,
                "username": username,
                "email": email
            }).execute()
        except Exception as e:
            print(f"[AUTH] User created but profile sync failed: {str(e)}")
            # We don't block the whole signup if just the profile table sync fails
            
        return jsonify({"message": "Signup successful! Please check your email for confirmation.", "user_id": res.user.id})
    except AuthApiError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
        
    try:
        res = database.supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        return jsonify({
            "message": "Login successful",
            "access_token": res.session.access_token,
            "user": {
                "id": res.user.id,
                "email": res.user.email,
                "name": res.user.user_metadata.get('full_name'),
                "username": res.user.user_metadata.get('username')
            }
        })
    except AuthApiError as e:
        return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500

if __name__ == '__main__':
    print("🚀 ShieldByte Backend is running...")
    print("👉 Local: http://127.0.0.1:5000")
    print("👉 Network: http://(your-ip-address):5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
