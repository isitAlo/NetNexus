import scapy.all as scapy
import socket

def get_hostname(ip):
    """
    Tries multiple protocols to find the name.
    """
    # 1. Try Standard DNS
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        pass

    # 2. Try NetBIOS (The best way to find a PS5 or PC)
    try:
        # Sending a NetBIOS Name Service (NBNS) query
        nbns_query = scapy.IP(dst=ip)/scapy.UDP(sport=137, dport=137)/scapy.NBNSQueryRequest(QUESTION_NAME="*")
        ans = scapy.sr1(nbns_query, timeout=0.5, verbose=False)
        if ans:
            return ans.getlayer(scapy.NBNSQueryRequest).QUESTION_NAME.decode().strip()
    except:
        pass

    return "Unknown Device"

def scan(ip_range):
    """
    Active discovery using ARP, ICMP, and NetBIOS.
    """
    print(f"[*] Deep scanning {ip_range}...")
    
    # Send ARP broadcast
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast/arp_request
    
    # We increase the timeout to 3 seconds for slower devices like the PS5
    answered_list = scapy.srp(combined_packet, timeout=3, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        name = get_hostname(ip)
        
        devices_list.append({"ip": ip, "mac": mac, "name": name})
            
    return devices_list
