import json
from datetime import datetime

def generate_report(scan_data):
    """
    Generates a structured report from the scan data.
    """
    report = {
        "scan_id": scan_data.get("id", "N/A"),
        "target": scan_data.get("target"),
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_vulnerabilities": len(scan_data.get("zap", [])),
            "risk_level": scan_data.get("riskLevel"),
            "open_ports": len(scan_data.get("nmap", []))
        },
        "details": {
            "web_vulnerabilities": scan_data.get("zap", []),
            "network_services": scan_data.get("nmap", [])
        }
    }
    
    # In the future, this function could also generate a PDF
    # using libraries like reportlab or fpdf
    
    return report
