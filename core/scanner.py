import scapy.all as scapy
import socket
from concurrent.futures import ThreadPoolExecutor

def get_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def scan(ip_range, device_memory):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    
    ips_to_resolve = []
    for element in ans:
        ip = element[1].psrc
        mac = element[1].hwsrc
        if ip not in device_memory:
            device_memory[ip] = {"ip": ip, "mac": mac, "name": "Resolving..."}
            ips_to_resolve.append(ip)
            
    if ips_to_resolve:
        with ThreadPoolExecutor(max_workers=50) as executor:
            names = list(executor.map(get_name, ips_to_resolve))
            
        for ip, name in zip(ips_to_resolve, names):
            device_memory[ip]["name"] = name
