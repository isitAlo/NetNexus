import subprocess

def apply_limit(iface, kbps):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
    
    cmd = [
        "sudo", "tc", "qdisc", "add", "dev", iface, "root", "tbf",
        "rate", f"{kbps}kbit", "latency", "50ms", "burst", "1540"
    ]
    subprocess.run(cmd, check=True)

def reset_shaper(iface):
    # Clears all limits and returns the interface to full speed
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
