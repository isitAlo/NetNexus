import scapy.all as scapy
import subprocess

def get_hostname(ip):
    try:
        output = subprocess.check_output(f"nmap -sL {ip}", shell=True).decode()
        if "report for" in output:
            name = output.split("report for")[1].split("(")[0].strip()
            if not name.replace(".", "").isnumeric():
                return name
    except:
        pass
    return "Unknown Device"

def scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=3, verbose=False)[0]
    return [{"ip": e[1].psrc, "mac": e[1].hwsrc, "name": get_hostname(e[1].psrc)} for e in ans]
