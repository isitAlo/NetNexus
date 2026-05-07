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
