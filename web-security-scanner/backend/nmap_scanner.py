import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor

# ---------------- CONFIG ----------------
SOCKET_TIMEOUT = 0.5
ASYNC_LIMIT = 500       # max async connections
THREADS = 50
# --------------------------------------

# --------- NMAP CHECK ----------
HAS_NMAP = False
try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
# -------------------------------

def get_target_host(target_url):
    return target_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

# ---------------- NMAP SCAN ----------------
def run_nmap_scan(target_url, scan_mode):
    hostname = get_target_host(target_url)
    print(f"[NMAP] Running Nmap scan ({scan_mode}) on {hostname}")

    nm = nmap.PortScanner()

    if scan_mode == "deep":
        args = "-sV -p 1-1000 -T4"
    elif scan_mode == "balanced":
        args = "-sV --top-ports 100 -T4"
    else:
        args = "-F -T4"

    nm.scan(hosts=hostname, arguments=args)

    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, data in nm[host][proto].items():
                if data["state"] == "open":
                    results.append({
                        "port": port,
                        "service": data.get("name", "unknown"),
                        "state": "open",
                        "version": data.get("version", "")
                    })

    return results

# --------------- ASYNC SOCKET SCAN ----------------
async def scan_port_async(semaphore, host, port):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=SOCKET_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()

            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"

            return {
                "port": port,
                "service": service,
                "state": "open",
                "version": ""
            }
        except:
            return None

async def async_socket_scan(host, ports):
    semaphore = asyncio.Semaphore(ASYNC_LIMIT)
    tasks = [scan_port_async(semaphore, host, port) for port in ports]

    results = []
    for task in asyncio.as_completed(tasks):
        result = await task
        if result:
            results.append(result)

    return results

# --------------- MAIN FALLBACK SCAN ----------------
def run_socket_scan(target_url, scan_mode):
    hostname = get_target_host(target_url)

    try:
        target_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        print("[ERROR] DNS resolution failed")
        return []

    print(f"[SOCKET] Async scan on {target_ip} ({scan_mode})")

    if scan_mode == "deep":
        ports = range(1, 1025)
    elif scan_mode == "balanced":
        ports = [
            20, 21, 22, 23, 25, 53, 80, 110, 143,
            443, 445, 993, 995, 3306, 3389, 8080
        ]
    else:
        ports = [21, 22, 80, 443, 3306, 3389, 8080]

    return asyncio.run(async_socket_scan(target_ip, ports))

# --------------- MAIN FUNCTION ----------------
def run_scan(target_url, scan_mode="fast"):
    if HAS_NMAP:
        try:
            return run_nmap_scan(target_url, scan_mode)
        except Exception as e:
            # Common error: 'nmap' not found in PATH
            if "nmap program was not found" in str(e) or "No such file" in str(e):
                print(f"[WARNING] Nmap not found in system PATH. Please install Nmap from https://nmap.org/download.html")
            else:
                print(f"[WARNING] Nmap failed: {e}")
            
            print("[INFO] Falling back to Python-based async socket scan (slower but works without Nmap)...")

    return run_socket_scan(target_url, scan_mode)

# --------------- EXAMPLE ----------------
if __name__ == "__main__":
    target = "http://scanme.nmap.org"
    results = run_scan(target, "fast")

    for r in results:
        print(r)
