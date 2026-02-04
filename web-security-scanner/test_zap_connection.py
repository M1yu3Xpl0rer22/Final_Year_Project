import requests
import sys

# Try both localhost and 127.0.0.1 just in case
urls = ['http://localhost:8080', 'http://127.0.0.1:8080']

print("Diagnosing ZAP Connection...")

for url in urls:
    print(f"\nTesting {url} ...")
    try:
        response = requests.get(url, timeout=2)
        print(f"SUCCESS! Connected to {url}")
        print(f"Status Code: {response.status_code}")
        print("Server Headers:", response.headers)
        if response.status_code == 200:
            print("ZAP is running and accessible.")
        elif response.status_code == 403:
            print("ZAP is reachable but access is forbidden. API Key might be required.")
    except requests.exceptions.ConnectionError:
        print(f"FAILED. Could not connect to {url}. Is ZAP running on port 8080?")
    except Exception as e:
        print(f"ERROR: {e}")
