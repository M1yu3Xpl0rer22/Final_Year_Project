import subprocess
import json
import tempfile
import os

def run_nuclei_scan(target_url):
    """
    Runs Nuclei scanner using the command line tool.
    Returns a list of vulnerability objects.
    """
    output_file = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp:
            output_file = temp.name

        # Determine binary path: check local directory first
        local_nuclei = os.path.join(os.path.dirname(__file__), "nuclei.exe")
        nuclei_cmd = local_nuclei if os.path.exists(local_nuclei) else "nuclei"

        command = [
            nuclei_cmd,
            "-u", target_url,
            "-tags", "owasp,generic,tech-detect,php,exposure",
            "-ni", # Non-interactive
            "-je", output_file # Use JSON Export flag
        ]

        print(f"[NUCLEI] Starting scan on {target_url} using {nuclei_cmd}...")
        # Capture stderr to see actual error message
        result = subprocess.run(command, check=True, capture_output=True, text=True)

        results = []
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r") as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        results = data
                    else:
                        results = [data]
                except json.JSONDecodeError:
                    # Fallback for line-delimited JSON if Nuclei behaves unexpectedly
                    f.seek(0)
                    for line in f:
                        if line.strip():
                            results.append(json.loads(line))
        
        print(f"[NUCLEI] Scan complete. Found {len(results)} vulnerabilities.")
        return results

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Nuclei failed with exit status {e.returncode}")
        print(f"[ERROR] Nuclei Stdout: {e.stdout}")
        print(f"[ERROR] Nuclei Stderr: {e.stderr}")
        return []
    except FileNotFoundError:
        print(f"[WARNING] Nuclei binary not found.")
        return []
    except Exception as e:
        print(f"[ERROR] Unexpected nuclei error: {e}")
        return []
    finally:
        if output_file and os.path.exists(output_file):
            os.remove(output_file)
