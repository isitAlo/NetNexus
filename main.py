import scapy.all as scapy
import os, time, sys, subprocess, threading, platform
from core import scanner, spoof

# Detects 'Linux' or 'Windows'
current_os = platform.system()

def is_admin():
    """Checks for Root (Linux) or Admin (Windows) privileges."""
    try:
        if current_os == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0
    except:
        return False

def set_forwarding(state):
    """Universal forwarding control using platform-specific commands."""
    if current_os == "Linux":
        if state:
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        else:
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], capture_output=True)
    elif current_os == "Windows":
        iface_name = scapy.conf.iface.name
        val = "enabled" if state else "disabled"
        # Windows command to toggle forwarding
        subprocess.run(["netsh", "interface", "ipv4", "set", "interface", iface_name, f"forwarding={val}"], capture_output=True)

def main():
    if not is_admin():
        print(f"[-] Please run as Admin/Root on {current_os}.")
        return

    # Default Gateway (Check with 'ipconfig' on Windows)
    gateway_ip = "192.168.1.1" 
    ip_range = f"{gateway_ip}/24"

    print(f"[*] Starting NetNexus on {current_os}...")
    # ... rest of your logic to scan and spoof ...
