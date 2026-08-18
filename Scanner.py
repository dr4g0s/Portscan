#!/usr/bin/env python3
"""
Custom port scanner.

Accepts a URL, hostname or IP address, resolves it to an IP, checks whether the
host is actually up, and only then runs a port scan.

    python3 portscan.py                    # prompts for a target
    python3 portscan.py 192.168.1.10       # scan directly
    python3 portscan.py https://example.com/path --profile full

Requires the nmap binary as well as the python-nmap wrapper:
    sudo pacman -S nmap && pip install python-nmap        # Arch
    sudo apt install nmap && pip install python-nmap      # Debian/Ubuntu

Only scan hosts you own or have explicit written permission to test.
Unauthorised scanning is a criminal offence in most jurisdictions.
"""

import argparse
import ipaddress
import socket
import sys
from urllib.parse import urlparse

try:
    import nmap
except ImportError:
    sys.exit("python-nmap is not installed.  Run:  pip install python-nmap")


# ---------------------------------------------------------------------------
# Scan profiles
#
# The original script scanned all 65,535 ports with -T4 by default. That is a
# 10-45 minute operation on a single host and the most common reason a scan
# looks "broken" — it is still running. Default to the top 1000 ports (which is
# what plain `nmap` does) and make the full sweep an explicit choice.
# ---------------------------------------------------------------------------
PROFILES = {
    "quick":   {"ports": "1-1024",  "args": "-T4",             "desc": "well-known ports, fastest"},
    "default": {"ports": None,      "args": "-T4",             "desc": "nmap's top 1000 ports"},
    "full":    {"ports": "1-65535", "args": "-T4",             "desc": "every port — slow, minutes to an hour"},
    "service": {"ports": None,      "args": "-T4 -sV",         "desc": "top 1000 with version detection"},
}


def extract_hostname(raw: str) -> str:
    """Pull a bare hostname or IP out of whatever the user typed.

    Handles 'https://example.com/path?q=1', 'example.com:8080', 'example.com'
    and plain IPs. urlparse needs a scheme to populate .netloc, so add a
    throwaway one when it is missing.
    """
    raw = raw.strip()
    if not raw:
        return ""

    if "//" not in raw:
        raw = "//" + raw

    parsed = urlparse(raw)
    host = parsed.hostname or ""      # .hostname strips port and lowercases
    return host


def resolve(host: str) -> tuple[str, list[str]]:
    """Return (primary_ip, all_ips). Raises socket.gaierror if DNS fails."""
    try:
        # Already an IP? Then there is nothing to resolve.
        ipaddress.ip_address(host)
        return host, [host]
    except ValueError:
        pass

    # getaddrinfo catches every A/AAAA record, not just the first one. Large
    # sites round-robin across many addresses and you scanned only one of them.
    infos = socket.getaddrinfo(host, None)
    ips = sorted({info[4][0] for info in infos})
    return ips[0], ips


def is_host_up(scanner: nmap.PortScanner, ip: str) -> tuple[bool, str]:
    """Host discovery only (-sn), no port scan. Fast, and answers the question
    'is there anything there' before committing to a long scan.

    Returns (up, reason). Note that 'down' here means 'did not respond to our
    probes' — a host behind a firewall that drops pings looks identical to a
    host that is switched off. That is why -Pn exists.
    """
    scanner.scan(hosts=ip, arguments="-sn -T4")

    if ip not in scanner.all_hosts():
        return False, "no response to host discovery probes"

    state = scanner[ip].state()
    reason = ""
    try:
        reason = scanner[ip]["status"].get("reason", "")
    except (KeyError, TypeError):
        pass
    return state == "up", reason or state


def scan_ports(scanner: nmap.PortScanner, ip: str, profile: dict, treat_as_up: bool) -> None:
    """Run the port scan and print the results."""
    args = profile["args"]
    if treat_as_up:
        # -Pn: skip discovery and scan anyway. Needed for hosts that drop ICMP.
        args += " -Pn"

    ports = profile["ports"]
    print(f"\nScanning {ip} — {profile['desc']}")
    print("This can take a while. Leave it running.\n")

    scanner.scan(hosts=ip, ports=ports, arguments=args)

    if ip not in scanner.all_hosts():
        print("The scan returned no data for this host.")
        return

    host_data = scanner[ip]
    hostname = host_data.hostname()
    print(f"Host      : {ip}" + (f" ({hostname})" if hostname else ""))
    print(f"State     : {host_data.state()}")

    found_any = False
    closed_count = 0

    for proto in host_data.all_protocols():
        all_ports = sorted(host_data[proto].keys())

        # Only report ports that are actually interesting. A full 65,535-port
        # scan would otherwise print 65,000 lines of "closed", which buries the
        # handful of results you care about. This is what real nmap does.
        interesting = [
            p for p in all_ports
            if host_data[proto][p].get("state") in ("open", "open|filtered", "filtered")
        ]
        closed_count += len(all_ports) - len(interesting)

        if not interesting:
            continue
        found_any = True

        print(f"\nProtocol  : {proto}")
        print(f"{'PORT':<10}{'STATE':<16}{'SERVICE':<18}VERSION")
        print("-" * 66)

        for port in interesting:
            info = host_data[proto][port]
            version = " ".join(
                part for part in (info.get("product", ""), info.get("version", "")) if part
            )
            print(
                f"{port:<10}{info.get('state', '?'):<16}"
                f"{info.get('name', 'unknown'):<18}{version}"
            )

    if closed_count:
        print(f"\nNot shown: {closed_count} closed port(s).")

    if not found_any:
        print("\nNo open ports found in the scanned range.")
        print("The host is up but either has nothing listening, or a firewall")
        print("is filtering the ports you scanned.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve a target and scan it for open ports.",
        epilog="Only scan systems you own or are authorised to test.",
    )
    parser.add_argument("target", nargs="?", help="URL, hostname or IP address")
    parser.add_argument(
        "-p", "--profile", default="default", choices=list(PROFILES),
        help="scan profile (default: %(default)s)",
    )
    parser.add_argument(
        "-Pn", "--skip-discovery", action="store_true",
        help="scan even if the host appears down (it may just be dropping pings)",
    )
    args = parser.parse_args()

    raw = args.target or input("Enter a URL, hostname or IP address: ")

    # --- resolve ----------------------------------------------------------
    host = extract_hostname(raw)
    if not host:
        print("That does not look like a valid target.")
        return 1

    print(f"\nTarget    : {host}")
    try:
        ip, all_ips = resolve(host)
    except socket.gaierror:
        print(f"Could not resolve '{host}'. Check the spelling and your DNS.")
        return 1

    print(f"Resolved  : {ip}")
    if len(all_ips) > 1:
        print(f"            (also {', '.join(all_ips[1:])} — scanning the first only)")

    # --- scanner ----------------------------------------------------------
    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError:
        print("\nThe nmap binary was not found. python-nmap is only a wrapper.")
        print("Install it with:  sudo pacman -S nmap")
        return 1

    # --- is it up? --------------------------------------------------------
    print("\nChecking whether the host is up...")
    try:
        up, reason = is_host_up(scanner, ip)
    except nmap.PortScannerError as exc:
        print(f"Host discovery failed: {exc}")
        return 1

    if up:
        print(f"Host is UP ({reason})")
    else:
        print(f"Host appears DOWN ({reason})")
        if not args.skip_discovery:
            print("\nNothing responded to the discovery probes. The host may be")
            print("switched off, unreachable, or configured to drop pings.")
            print("To scan it anyway, re-run with  -Pn")
            return 0
        print("Continuing anyway because -Pn was given.")

    # --- scan -------------------------------------------------------------
    try:
        scan_ports(scanner, ip, PROFILES[args.profile], treat_as_up=(not up))
    except nmap.PortScannerError as exc:
        print(f"\nScan failed: {exc}")
        print("Some scan types need root. Try running with sudo.")
        return 1
    except KeyboardInterrupt:
        print("\n\nScan interrupted.")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
