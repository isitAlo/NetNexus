import scapy.all as scapy
import subprocess

def get_hostname(ip):
    try:
        # Use nmap for accurate device naming
        output = subprocess.check_output(f"nmap -sL {ip}", shell=True, stderr=subprocess.DEVNULL).decode()
        if "report for" in output:
            name = output.split("report for")[1].split("(")[0].strip()
            return name if not name.replace(".", "").isnumeric() else "Unknown"
    except: pass
    return "Unknown Device"

def scan(ip_range, device_memory):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    for element in ans:
        ip, mac = element[1].psrc, element[1].hwsrc
        if ip not in device_memory:
            device_memory[ip] = {"ip": ip, "mac": mac, "name": get_hostname(ip)}
    return device_memory
