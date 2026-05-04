import os

def set_ip_forwarding(enable=True):
    state = "1" if enable else "0"
    os.system(f"echo {state} > /proc/sys/net/ipv4/ip_forward")

def apply_limit(target_ip, interface, download_kbps):
    """Limits download speed using Linux Traffic Control (tc)."""
    # Clear existing rules
    os.system(f"sudo tc qdisc del dev {interface} root 2>/dev/null")
    
    # Create a new hierarchy (HTB)
    os.system(f"sudo tc qdisc add dev {interface} root handle 1: htb default 10")
    os.system(f"sudo tc class add dev {interface} parent 1: classid 1:1 htb rate {download_kbps}kbps")
    
    # Mark packets from target IP to apply the limit
    os.system(f"sudo iptables -t mangle -A FORWARD -d {target_ip} -j MARK --set-mark 1")
    os.system(f"sudo tc filter add dev {interface} protocol ip parent 1:0 prio 1 handle 1 fw flowid 1:1")

def reset_network(interface):
    os.system(f"sudo tc qdisc del dev {interface} root 2>/dev/null")
    os.system("sudo iptables -t mangle -F")
    set_ip_forwarding(True)