import scapy.all as scapy
import socket

def get_hostname(ip):
    """Enhanced name lookup."""
    try:
        # Standard DNS/Reverse DNS
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout):
        try:
            # Try to get name via NetBIOS (common for Windows/Consoles)
            return socket.gethostbyname(ip)
        except:
            return "Unknown Device"

def scan(ip_range):
    """
    Combined ARP and ICMP scan for better discovery.
    """
    print(f"[*] Scanning {ip_range}...")
    
    # 1. ARP Scan (Fastest for most devices)
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices_list = []
    seen_ips = set()

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        name = get_hostname(ip)
        
        if ip not in seen_ips:
            devices_list.append({"ip": ip, "mac": mac, "name": name})
            seen_ips.add(ip)

    # 2. ICMP (Ping) Scan for 'silent' devices that ignore ARP
    # This wakes up devices like the PS5 or sleeping phones
    ping_request = scapy.IP(dst=ip_range)/scapy.ICMP()
    ans = scapy.sr(ping_request, timeout=1, verbose=False)[0]
    
    for sent, received in ans:
        if received.src not in seen_ips:
            # If we find a new IP via Ping, try to get its MAC
            mac = "Unknown MAC"
            name = get_hostname(received.src)
            devices_list.append({"ip": received.src, "mac": mac, "name": name})
            seen_ips.add(received.src)
            
    return devices_list
