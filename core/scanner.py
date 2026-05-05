import scapy.all as scapy
import socket
import subprocess

def get_hostname(ip):
    """Deep scan for names using DNS, NetBIOS, and Nmap fallback."""
    # Method 1: Standard DNS
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        pass

    # Method 2: System Nmap (Best for Arch Linux to find PS5/Phones)
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
    """ARP Scan with name resolution."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=3, verbose=False)[0]

    devices_list = []
    for element in ans:
        ip = element[1].psrc
        devices_list.append({
            "ip": ip,
            "mac": element[1].hwsrc,
            "name": get_hostname(ip)
        })
    return devices_list
