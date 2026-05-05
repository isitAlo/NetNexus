import scapy.all as scapy
import os
import time
from core import scanner, spoof

def main():
    # CONFIGURATION
    # Run 'ip a' and put your interface name here (e.g., wlan0)
    scapy.conf.iface = "wlan0" 
    
    if os.geteuid() != 0:
        print("[-] Please run with: sudo python main.py")
        return

    gateway_ip = "192.168.8.1"
    target_ip = "192.168.8.5" # Your PS5 IP

    print(f"[*] Starting NetNexus on {scapy.conf.iface}")
    print(f"[*] Target: {target_ip} | Gateway: {gateway_ip}")

    # Get MAC addresses
    target_mac, _ = spoof.get_device_info(target_ip)
    gateway_mac, _ = spoof.get_device_info(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[-] Failed to find MAC addresses. Is the PS5 on?")
        return

    try:
        print("[*] Spoofing started. Press Ctrl+C to stop.")
        while True:
            # Aggressive 0.5s timing for PS5 stability
            spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
            time.sleep(0.5) 
    except KeyboardInterrupt:
        print("\n[*] Restoring network...")
        spoof.restore(target_ip, gateway_ip)
        spoof.restore(gateway_ip, target_ip)
        print("[+] Done.")

if __name__ == "__main__":
    main()
