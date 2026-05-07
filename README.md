# NetNexus

A modular Python-based network tool for Linux designed for device discovery, ARP spoofing, and traffic shaping.

### Features
* **Live Discovery**: Background scanning thread for real-time device updates.
* **Traffic Shaping**: Limit target bandwidth in **kbps** using Linux `tc` (Traffic Control).
* **Connection Kill**: Instantly sever a target's internet connection.
* **Auto-Cleanup**: Automatically restores ARP tables and resets network interfaces on exit.
* **Modular Engine**: Clean separation between scanning, spoofing, and shaping logic.

---

### Project Structure
```text
NetNexus/
├── main.py           # User Interface & Control Loop
└── core/
    ├── scanner.py    # ARP Scanning & Name Resolution
    ├── spoof.py      # ARP Poisoning & Restore Logic
    ├── shaper.py     # Traffic Control (kbps limiting)
    └── __init__.py   # Package Initializer
Prerequisites
OS: Linux (Optimized for Arch Linux).

Permissions: Root privileges required for raw packet injection and network modifications.

Dependencies:

Python 3.x

scapy

iproute2 (for tc support)

Installation
Clone the repository:

Bash
git clone [https://github.com/isitAlo/NetNexus.git](https://github.com/isitAlo/NetNexus.git)
cd NetNexus
Install Python dependencies:

Bash
pip install scapy
Usage
Run as Root:

Bash
sudo python main.py
The Interface:

The tool automatically scans the local network upon startup.

Enter the ID of the target device from the generated list.

Choose [1] to Limit bandwidth (specify speed in kbps).

Choose [2] to Kill the connection.

Stopping:

Press Ctrl+C during an attack to return to the device menu.

Press q in the main menu to exit and trigger automatic network cleanup.

Technical Breakdown
NetNexus functions by positioning the host machine as a Man-in-the-Middle (MITM).

Scanner: Maps IP/MAC addresses via ARP and resolves hostnames using the socket library.

Spoof: Injects forged ARP replies to redirect target traffic through the host.

Shaper: Implements a Token Bucket Filter (TBF) via the Linux kernel to throttle packet throughput.
