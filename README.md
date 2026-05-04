# NetNexus 🛡️
An open-source Linux utility to manage and limit internet usage on local networks using ARP Spoofing and Traffic Shaping.

## Features
* **Auto-Discovery:** Automatically scans the network and detects the Gateway.
* **Kill Switch:** Cut internet access for any specific device.
* **Bandwidth Limiter:** Limit download speeds (kbps) for specific targets.
* **No Configuration Needed:** Detects network interfaces and IPs automatically.

## Installation
1. Clone the repo:
   `git clone https://github.com/isitAlo/NetNexus.git`
2. Install dependencies:
   `pip install -r requirements.txt`
3. Ensure you have `iptables` and `iproute2` installed on your Linux system.

## Usage
Run with root privileges:
`sudo python3 main.py`

## Disclaimer
This tool is for **educational and home management purposes only**. Unauthorized use on networks you do not own is strictly prohibited.