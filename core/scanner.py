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

def scan(ip_range, existing_devices):
    """Scans and merges new results with the existing device list."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]

    for element in ans:
        ip = element[1].psrc
        mac = element[1].hwsrc
        # Only add if it's a new IP or the MAC changed
        if ip not in existing_devices or existing_devices[ip]['mac'] != mac:
            existing_devices[ip] = {
                "ip": ip,
                "mac": mac,
                "name": get_hostname(ip)
            }
    return existing_devices
