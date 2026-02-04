from zapv2 import ZAPv2
import time
import sys

# Define target
target = 'https://testphp.vulnweb.com/'
# ZAP URL
zap_proxy = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
api_key = '' # User said they might have disabled it, or it's missing.

print("Testing ZAP Library Connection...")
try:
    print(f"Connecting to ZAP at {zap_proxy}...")
    zap = ZAPv2(apikey=api_key, proxies=zap_proxy)
    
    print("Attempting to access ZAP API version...")
    version = zap.core.version
    print(f"SUCCESS! ZAP Version: {version}")
    
    print("Attempting to access target...")
    zap.urlopen(target)
    print("SUCCESS! Accessed target.")

except Exception as e:
    print("\n[FAILURE]")
    print(f"Error: {e}")
    print("\nTROUBLESHOOTING:")
    print("1. 'RemoteDisconnected' usually means ZAP rejected the connection.")
    print("2. Did you disable the API Key in Tools > Options > API?")
    print("3. Is 'Addresses permitted to use the API' set to permit 127.0.0.1?")
