import time
import requests
import json

# Default ZAP API configuration
ZAP_API_URL = 'http://localhost:8080'
ZAP_API_KEY = 'etrb1goo7fiefh7cl05ht9418e' # Leave empty if API key is disabled in ZAP options

def run_zap_scan(target_url, scan_options=None):
    """
    Runs a REAL OWASP ZAP scan against the target URL.
    Uses direct requests to avoid proxy library issues.
    """
    print(f"[ZAP] Connecting to ZAP API at {ZAP_API_URL}...")
    headers = {
        'Accept': 'application/json',
        'X-ZAP-API-Key': ZAP_API_KEY
    }
    
    # Helper to clean text response
    def get_json(resp):
        try: return resp.json()
        except: return {}

    try:
        # 0. Check connection & Start New Session
        try:
            r = requests.get(f"{ZAP_API_URL}/JSON/core/view/version/", headers=headers, timeout=5)
            print(f"[ZAP] Connected. Version: {get_json(r).get('version', 'Unknown')}")
            
            # Start a fresh session to avoid stale alerts from previous scans
            requests.get(f"{ZAP_API_URL}/JSON/core/action/newSession/", 
                        params={'name': 'ShieldByte_Session', 'overwrite': 'true'}, headers=headers)
            print("[ZAP] Initialized fresh ZAP session.")
            
        except requests.exceptions.RequestException:
             raise Exception("Could not connect to ZAP Server on port 8080")

        # 1. Access the target
        print(f"[ZAP] Accessing target: {target_url}")
        requests.get(f"{ZAP_API_URL}/JSON/core/action/accessUrl/", 
                    params={'url': target_url}, headers=headers)
        time.sleep(2)

        # 2. Spider
        print(f"[ZAP] Starting Spider for {target_url}...")
        r = requests.get(f"{ZAP_API_URL}/JSON/spider/action/scan/", 
                        params={'url': target_url}, headers=headers)
        scan_id = get_json(r).get('scan')
        
        if scan_id:
            start_time = time.time()
            last_status = -1
            while True:
                r = requests.get(f"{ZAP_API_URL}/JSON/spider/view/status/", 
                                params={'scanId': scan_id}, headers=headers)
                status = int(get_json(r).get('status', 0))
                
                # Only print updates if percentage changed
                if status != last_status:
                    print(f"[ZAP] Spider progress: {status}%")
                    last_status = status
                    
                if status >= 100 or time.time() - start_time > 180: # Increased timeout
                    break
                time.sleep(2)

        # 3. Active Scan
        print(f"[ZAP] Starting Active Scan for {target_url}...")
        
        # Configure Granular Scanning if options present
        if scan_options and len(scan_options) > 0:
             print(f"[ZAP] Applying scan options: {scan_options}")
             requests.get(f"{ZAP_API_URL}/JSON/ascan/action/disableAllScanners/", headers=headers)
             # Basic mapping for demo
             ids_to_enable = "40018,40019" # Default SQLi
             requests.get(f"{ZAP_API_URL}/JSON/ascan/action/enableScanners/", 
                         params={'ids': ids_to_enable}, headers=headers)
        else:
             print("[ZAP] No specific options selected. Running FULL Active Scan (this may take time).")
        
        r = requests.get(f"{ZAP_API_URL}/JSON/ascan/action/scan/", 
                        params={'url': target_url}, headers=headers)
        ascan_id = get_json(r).get('scan')
        
        if ascan_id:
            start_time = time.time()
            last_status = -1
            while True:
                r = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/status/", 
                                params={'scanId': ascan_id}, headers=headers)
                status = int(get_json(r).get('status', 0))
                
                # Only print updates if percentage changed
                if status != last_status:
                    print(f"[ZAP] Active Scan progress: {status}%")
                    last_status = status
                    
                if status >= 100 or time.time() - start_time > 600: # Increased timeout to 10 mins
                    break
                time.sleep(5)
        
        # 4. Get Alerts
        r = requests.get(f"{ZAP_API_URL}/JSON/core/view/alerts/", 
                        params={'baseurl': target_url}, headers=headers)
        alerts = get_json(r).get('alerts', [])
        
        vulnerabilities = []
        for alert in alerts:
            vulnerabilities.append({
                "type": alert.get('alert', 'Unknown'),
                "severity": alert.get('risk', 'Low'),
                "description": alert.get('description', '')[:200] + "...",
                "location": target_url
            })
            
        print(f"[ZAP] Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities

    except Exception as e:
        print(f"[ZAP] Error connecting to ZAP: {e}")
        return [{
            "type": "ZAP Connection Error",
            "severity": "Critical",
            "description": f"Details: {str(e)}\n\nCheck ZAP is running and API Key is disabled/correct.",
            "location": "Localhost"
        }]
