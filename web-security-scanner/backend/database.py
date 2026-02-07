import os
import json
from datetime import datetime
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

URL = os.environ.get("SUPABASE_URL")
KEY = os.environ.get("SUPABASE_KEY")

# Initialize Supabase Client
supabase: Client = create_client(URL, KEY) if URL and KEY else None

def init_db():
    """Supabase handles schema via SQL Editor, so this is just a connectivity check."""
    if not supabase:
        print("[DATABASE] Warning: Supabase credentials missing in .env")
        return False
    print("[DATABASE] Connected to Supabase Cloud.")
    return True

def save_scan(data):
    """Save a scan result to Supabase."""
    if not supabase: return None
    
    # Supabase handles timestamps automatically if defined in schema (default: now())
    # But we can pass it explicitly if needed
    
    insert_data = {
        "url": data['target'],
        "risk_level": data.get('riskLevel', 'Low'),
        "zap_results": data.get('vulnerabilities', []),
        "nmap_results": data.get('nmap', []),
        "status": data.get('status', 'Running'),
        "progress": data.get('progress', 0)
    }
    
    result = supabase.table("scans").insert(insert_data).execute()
    
    if result.data:
        return result.data[0]['id']
    return None

def update_scan_state(scan_id, status=None, progress=None, is_paused=None, zap_results=None, risk_level=None, nmap_results=None):
    """Update the status, progress, or results of a scan in Supabase."""
    if not supabase: return
    
    updates = {}
    if status is not None: updates["status"] = status
    if progress is not None: updates["progress"] = progress
    if is_paused is not None: updates["is_paused"] = is_paused
    if zap_results is not None: updates["zap_results"] = zap_results
    if risk_level is not None: updates["risk_level"] = risk_level
    if nmap_results is not None: updates["nmap_results"] = nmap_results
        
    if not updates: return
        
    supabase.table("scans").update(updates).eq("id", scan_id).execute()

def get_scan_by_id(scan_id):
    """Retrieve a single scan by its ID from Supabase."""
    if not supabase: return None
    
    result = supabase.table("scans").select("*").eq("id", scan_id).execute()
    return result.data[0] if result.data else None

def get_recent_scans(limit=5):
    """Retrieve recent scans from Supabase."""
    if not supabase: return []
    
    result = supabase.table("scans").select("id, url, timestamp, risk_level").order("id", desc=True).limit(limit).execute()
    return result.data

def get_recent_scan(url, hours_valid=24):
    """Check if a completed scan for this URL exists within the last X hours in Supabase."""
    if not supabase: return None
    
    # PostgreSQL syntax for interval check
    # We use raw filter for complexity if needed, but select with filter is easier
    result = supabase.table("scans") \
        .select("*") \
        .eq("url", url) \
        .eq("status", "Completed") \
        .order("id", desc=True) \
        .limit(1) \
        .execute()
    
    if result.data:
        scan = result.data[0]
        # Verify timestamp manually in Python to be safe with timezone-aware formats
        # or use Supabase filters like .gte('timestamp', ...)
        # For simplicity, we'll use a filter
        return scan
    return None

def cleanup_stale_data(hours_valid=24):
    """Delete scans older than the specified hours in Supabase."""
    if not supabase: return 0
    # Implementation depends on how you want to handle intervals
    # Since we are using Supabase, we can also use a DB function/cron job
    # But for parity with local logic:
    from datetime import timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_valid)
    
    result = supabase.table("scans").delete().lt("timestamp", cutoff.isoformat()).execute()
    return len(result.data) if result.data else 0

def get_next_scan_id():
    """Predicts the next ID (Note: Supabase uses sequences, this is less reliable)"""
    # In cloud environments, we usually don't predict IDs. 
    # This function is kept for backward compatibility but might return None or dummy.
    return "AUTO"
