import scapy.all as scapy

def get_gateway_ip():
    """Automatically detects the router IP."""
    return scapy.conf.route.route("0.0.0.0")[2]

def scan_network():
    """Scans the local network for active devices."""
    gateway_ip = get_gateway_ip()
    network_prefix = ".".join(gateway_ip.split(".")[:-1]) + ".0/24"
    
    arp_request = scapy.ARP(pdst=network_prefix)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices