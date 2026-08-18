Python Port Scanner

A lightweight command-line wrapper around Nmap written in Python. It streamlines the scanning process by automatically resolving URLs/hostnames, performing pre-scan host discovery, and executing targeted port scans with clean, readable output.
Features

    Smart Target Parsing: Accepts bare IPs, hostnames (e.g., example.com), or full URLs (e.g., [https://example.com/path](https://example.com/path)) and resolves them to a primary IP.

    Pre-Scan Discovery: Uses ICMP/host discovery (-sn) to verify a host is online before committing to a time-consuming port scan.

    Custom Scan Profiles: Choose between quick sweeps, default Nmap top-1000, full 65,535 port sweeps, or service version detection.

    Clean Output: Filters out noise by only displaying open, filtered, or open|filtered ports, preventing terminal clutter from thousands of closed ports.

    Firewall Bypass: Includes a -Pn flag to force a scan on hosts that drop ping requests.
Prerequisites

This script requires the nmap system binary and the python-nmap library.

_**Arch Linux:**_

  sudo pacman -S nmap
  pip install python-nmap

_**Debian/Ubuntu:**_
  
  sudo apt install nmap
  pip install python-nmap

Usage

You can run the script interactively or provide arguments directly via the command line.
  # Interactive mode (prompts for a target)
python3 portscan.py

# Scan a direct IP or domain (uses the 'default' profile)
python3 portscan.py 192.168.1.10
python3 portscan.py https://example.com

# Specify a scan profile
python3 portscan.py 10.129.2.45 --profile quick
python3 portscan.py 10.129.2.45 -p service

# Force scan if the host blocks ping discovery
python3 portscan.py 10.129.2.45 -Pn


**Legal Warning: Only scan networks and hosts that you own or have explicit, written permission to test. Unauthorized port scanning is considered malicious behavior and is a criminal offense in most jurisdictions.**
