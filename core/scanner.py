import scapy.all as scapy
import socket

def get_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def scan(ip_range, device_memory):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    
    for element in ans:
        ip = element[1].psrc
        if ip not in device_memory:
            mac = element[1].hwsrc
            name = get_name(ip)
            device_memory[ip] = {"ip": ip, "mac": mac, "name": name}
