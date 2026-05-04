from core import scanner, spoof, shaper
import os

def display_devices(devices):
    print("\nID\tIP Address\t\tMAC Address\t\tDevice Name")
    print("-" * 75)
    for index, device in enumerate(devices):
        print(f"{index}\t{device['ip']}\t\t{device['mac']}\t{device['name']}")

def main():
    # Ensure tool is run with root on Arch Linux[cite: 2]
    if os.geteuid() != 0:
        print("[-] This tool must be run with sudo.")
        return

    print("--- NetNexus Network Manager ---")
    target_range = input("Enter network range (e.g., 192.168.1.1/24): ")
    
    print("[*] Scanning network...")
    devices = scanner.scan(target_range)
    display_devices(devices)

    # ... Rest of your logic for spoofing and shaping[cite: 2]
