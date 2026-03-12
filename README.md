Python Nmap Port Scanner
A robust, Python-based network utility designed for scanning open ports and identifying services on a target machine. This tool utilizes the python-nmap library to provide a programmatic interface for the Nmap scanning engine, making it ideal for security auditing in controlled lab environments.

Features
Full Range Scanning: Checks all 65,535 TCP ports.

Performance Optimized: Uses the -T4 timing template for faster execution.

Service Detection: Identifies the name of the service running on each open port.

Cross-Platform: Fully compatible with Arch Linux and Windows.


Prerequisites
1. System Requirements
You must have the Nmap binary installed on your system.

Arch Linux: sudo pacman -S nmap

Windows: Download the installer from nmap.org and ensure Nmap is added to your System PATH.

2. Python Library
Install the Nmap wrapper for Python:

Bash
pip install python-nmap

Usage
Clone the repository:

Bash
git clone https://github.com/dr4g0s/Portscan.git
cd Portscan


Run the script:
On Arch Linux, it is recommended to run with sudo to allow Nmap to use raw sockets for more accurate scanning:

Bash
sudo python scanner.py

Disclaimer
This tool is intended for educational purposes and authorized security testing only. Unauthorized scanning of networks or devices you do not own is illegal and unethical. Use this responsibly within your own lab environment.