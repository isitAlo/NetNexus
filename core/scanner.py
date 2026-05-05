import scapy.all as scapy
import subprocess

def get_hostname(ip):
    try:
        output = subprocess.check_output(f"nmap -sL {ip}", shell=True).decode()
        if "report for" in output:
            name = output.split("report for")[1].split("(")[0].strip()
            if not name.replace(".", "").isnumeric():
                return name
    except: pass
    return "Unknown Device"

def scan(ip_range, device_memory):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]
    for element in ans:
        ip, mac = element[1].psrc, element[1].hwsrc
        if ip not in device_memory or device_memory[ip]['mac'] != mac:
            device_memory[ip] = {"ip": ip, "mac": mac, "name": get_hostname(ip)}
    return device_memory
