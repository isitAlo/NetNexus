# NetNexus Network Manager

A professional ARP Spoofing and Network Discovery tool developed for Arch Linux. Optimized for high-performance devices and modern gaming consoles.

## 🚀 Features
* **Aggressive Spoofing**: 0.5s packet interval designed to bypass modern console security (tested on PS5).
* **Dual-Protocol Discovery**: Combined ARP and NetBIOS scanning to identify "hidden" device names.
* **Smart Restoration**: Automatically repairs target ARP tables upon exit to prevent network downtime.
* **Linux Optimized**: Built specifically for Arch Linux systems using Scapy.

## 🛠️ Requirements
* Python 3.x
* Scapy: `pip install scapy`
* Root privileges (sudo)

## 📖 Usage

1. **Enable IP Forwarding**:
   Before running the tool, allow your system to route traffic:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
