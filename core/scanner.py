import scapy.all as scapy
import socket

def get_hostname(ip):
    """Attempts to resolve an IP address to a hostname."""
    try:
        # Standard DNS/Reverse DNS lookup
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout):
        return "Unknown Device"

def scan(ip_range):
    """Scans the network for active devices and retrieves their names."""
    # Create ARP request for the specified range
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    # Send and receive packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        name = get_hostname(ip)
        
        device_details = {"ip": ip, "mac": mac, "name": name}
        devices_list.append(device_details)
        
    return devices_list
