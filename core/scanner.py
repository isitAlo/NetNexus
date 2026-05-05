import scapy.all as scapy
import socket

def get_hostname(ip):
    """Tries DNS and NetBIOS to find device names (like PS5)."""
    # Try Standard DNS
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        pass

    # Try NetBIOS (Best for Consoles/Windows)
    try:
        nbns_query = scapy.IP(dst=ip)/scapy.UDP(sport=137, dport=137)/scapy.NBNSQueryRequest(QUESTION_NAME="*")
        ans = scapy.sr1(nbns_query, timeout=0.5, verbose=False)
        if ans:
            return ans.getlayer(scapy.NBNSQueryRequest).QUESTION_NAME.decode().strip()
    except:
        pass

    return "Unknown Device"

def scan(ip_range):
    """Deep scan using ARP and name resolution."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    
    # 3 second timeout gives slow devices time to wake up
    answered_list = scapy.srp(packet, timeout=3, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        name = get_hostname(ip)
        devices_list.append({"ip": ip, "mac": mac, "name": name})
        
    return devices_list
