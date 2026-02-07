import threading
import time
import requests
import json
import zap
import nmap_scanner as nmap
import nuclei_scan
import database
from flask import jsonify

# ZAP API configuration (Should match zap.py)
ZAP_API_URL = 'http://localhost:8080'
ZAP_API_KEY = 'etrb1goo7fiefh7cl05ht9418e'
HEADERS = {
    'Accept': 'application/json',
    'X-ZAP-API-Key': ZAP_API_KEY
}

# In-memory tracking for active scans
active_scans = {} # scan_id -> { "spider_id": id, "ascan_id": id, "thread": thread, "stop_flag": bool }

def start_background_scan(target_url, scan_options, scan_mode):
    """Starts a scan in a background thread and returns the scan ID."""
    # 1. Create entry in DB
    scan_db_id = database.save_scan({
        "target": target_url,
        "riskLevel": "Low",
        "vulnerabilities": [],
        "nmap": []
    })
    
    # 2. Start background thread
    thread = threading.Thread(target=_run_scan_thread, args=(scan_db_id, target_url, scan_options, scan_mode))
    thread.daemon = True
    active_scans[scan_db_id] = {
        "spider_id": None,
        "ascan_id": None,
        "thread": thread,
        "stop_flag": False
    }
    thread.start()
    
    return scan_db_id

def _run_scan_thread(scan_id, target_url, scan_options, scan_mode):
    """Internal function to run the full scan sequence and update DB."""
    try:
        print(f"[MANAGER] Starting background scan {scan_id} for {target_url}")
        
        # --- ZAP Sequence ---
        # Initialize ZAP session
        requests.get(f"{ZAP_API_URL}/JSON/core/action/newSession/", 
                    params={'name': f'Scan_{scan_id}', 'overwrite': 'true'}, headers=HEADERS)
        
        requests.get(f"{ZAP_API_URL}/JSON/core/action/accessUrl/", 
                    params={'url': target_url}, headers=HEADERS)
        
        # Spider
        database.update_scan_state(scan_id, status="Spidering", progress=5)
        r = requests.get(f"{ZAP_API_URL}/JSON/spider/action/scan/", 
                        params={'url': target_url}, headers=HEADERS)
        spider_id = r.json().get('scan')
        active_scans[scan_id]["spider_id"] = spider_id
        
        while True:
            if active_scans[scan_id]["stop_flag"]: return
            try:
                r = requests.get(f"{ZAP_API_URL}/JSON/spider/view/status/", params={'scanId': spider_id}, headers=HEADERS, timeout=5)
                status = int(r.json().get('status', 0))
                database.update_scan_state(scan_id, progress=5 + int(status * 0.2)) # Spider is 20% of total
                if status >= 100: break
            except Exception as e:
                print(f"[MANAGER] Spider status error: {e}")
            time.sleep(2)

        # Active Scan
        database.update_scan_state(scan_id, status="Active Scanning", progress=25)
        try:
            r = requests.get(f"{ZAP_API_URL}/JSON/ascan/action/scan/", params={'url': target_url}, headers=HEADERS, timeout=5)
            ascan_id = r.json().get('scan')
            active_scans[scan_id]["ascan_id"] = ascan_id
        except Exception as e:
            print(f"[MANAGER] AScan start error: {e}")
            ascan_id = None
        
        if ascan_id:
            while True:
                if active_scans[scan_id]["stop_flag"]: return
                try:
                    r = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/status/", params={'scanId': ascan_id}, headers=HEADERS, timeout=5)
                    status = int(r.json().get('status', 0))
                    
                    # Periodically fetch partial alerts to show progress
                    alert_r = requests.get(f"{ZAP_API_URL}/JSON/core/view/alerts/", params={'baseurl': target_url}, headers=HEADERS, timeout=5)
                    alerts = alert_r.json().get('alerts', [])
                    vulnerabilities = []
                    risk_level = "Low"
                    
                    for a in alerts:
                        severity = a.get('risk', 'Low')
                        if severity == "Critical": risk_level = "Critical"
                        elif severity == "High" and risk_level != "Critical": risk_level = "High"
                        elif severity == "Medium" and risk_level not in ["Critical", "High"]: risk_level = "Medium"
                        
                        vulnerabilities.append({
                            "type": a.get('alert'), "severity": severity, 
                            "location": target_url, "source": "ZAP", "description": a.get('description', '')[:200]
                        })
                    
                    database.update_scan_state(scan_id, progress=25 + int(status * 0.5), zap_results=vulnerabilities, risk_level=risk_level)
                    if status >= 100: break
                except Exception as e:
                    print(f"[MANAGER] AScan status error: {e}")
                time.sleep(5)

        # Nmap & Nuclei
        database.update_scan_state(scan_id, status="Finalizing (Network/Service)", progress=80)
        try:
            nmap_results = nmap.run_scan(target_url, scan_mode)
            database.update_scan_state(scan_id, nmap_results=nmap_results)
        except Exception as e:
            print(f"[MANAGER] Nmap error: {e}")
            nmap_results = []

        try:
            nuclei_results = nuclei_scan.run_nuclei_scan(target_url)
            # Optionally merge nuclei results with ZAP results
        except Exception as e:
            print(f"[MANAGER] Nuclei error: {e}")
        
        # Complete
        database.update_scan_state(scan_id, status="Completed", progress=100)
        print(f"[MANAGER] Scan {scan_id} finished.")
        
    except Exception as e:
        print(f"[MANAGER] Fatal error in scan thread: {e}")
        database.update_scan_state(scan_id, status=f"Failed: {str(e)}")
    finally:
        if scan_id in active_scans:
            del active_scans[scan_id]

def control_scan(scan_id, action):
    """Processes pause, resume, or stop actions."""
    if scan_id not in active_scans:
        return {"error": "Scan not active or already finished"}, 404
        
    data = active_scans[scan_id]
    spider_id = data.get("spider_id")
    ascan_id = data.get("ascan_id")
    
    if action == "pause":
        if spider_id: requests.get(f"{ZAP_API_URL}/JSON/spider/action/pause/", params={'scanId': spider_id}, headers=HEADERS)
        if ascan_id: requests.get(f"{ZAP_API_URL}/JSON/ascan/action/pause/", params={'scanId': ascan_id}, headers=HEADERS)
        database.update_scan_state(scan_id, status="Paused", is_paused=True)
        return {"message": "Scan paused"}
        
    elif action == "resume":
        if spider_id: requests.get(f"{ZAP_API_URL}/JSON/spider/action/resume/", params={'scanId': spider_id}, headers=HEADERS)
        if ascan_id: requests.get(f"{ZAP_API_URL}/JSON/ascan/action/resume/", params={'scanId': ascan_id}, headers=HEADERS)
        database.update_scan_state(scan_id, status="Resuming...", is_paused=False)
        return {"message": "Scan resumed"}
        
    elif action == "stop":
        if spider_id: requests.get(f"{ZAP_API_URL}/JSON/spider/action/stop/", params={'scanId': spider_id}, headers=HEADERS)
        if ascan_id: requests.get(f"{ZAP_API_URL}/JSON/ascan/action/stop/", params={'scanId': ascan_id}, headers=HEADERS)
        if scan_id in active_scans:
            active_scans[scan_id]["stop_flag"] = True
        database.update_scan_state(scan_id, status="Stopped (Manual)", progress=100)
        return {"message": "Scan stopped"}
        
    return {"error": "Invalid action"}, 400
