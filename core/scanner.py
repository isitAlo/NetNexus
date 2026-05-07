import scapy.all as scapy

def scan(ip_range):
    devices = {}
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    for element in ans:
        ip = element[1].psrc
        mac = element[1].hwsrc
        devices[ip] = {"ip": ip, "mac": mac}
    return devices
