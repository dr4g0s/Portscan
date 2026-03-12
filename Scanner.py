# from python-nmap import nmap
import nmap

def scan_lab_machine(target_ip):
    # Starts this port scanner script 
    nm = nmap.PortScanner()
    
    print(f"Scanning {target_ip} for open ports...")
    
    # -p 1-65535: Scans all ports until 65535
    # -T4: This speeds up the port scanning process as there are 65k ports. Although this will increase the network traffic compared to -t1 or -t2. Can also add -A which does aggresive scanning
    nm.scan(target_ip, '1-65535', '-T4')
    
    for host in nm.all_hosts():
        print(f"\nHost : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")
        
        for proto in nm[host].all_protocols():
            print(f"Protocol : {proto}")
            
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                print(f"Port : {port}\tState : {state}\tService : {service}")

if __name__ == "__main__":
    # Replace with your own IP address or VM IP
    target = "input(enter your IP in here in here)" 
    scan_lab_machine(target)