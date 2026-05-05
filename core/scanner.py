import scapy.all as scapy
import subprocess

def get_hostname(ip):
    """Fallback name discovery using system nmap for Arch Linux."""
    try:
        output = subprocess.check_output(f"nmap -sL {ip}", shell=True).decode()
        if "report for" in output:
            return output.split("report for")[1].split("(")[0].strip()
    except:
        pass
    return "Unknown Device"

def scan(ip_range):
    """Performs an ARP scan of the network."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=3, verbose=False)[0]
    return [{"ip": e[1].psrc, "mac": e[1].hwsrc, "name": get_hostname(e[1].psrc)} for e in ans]
