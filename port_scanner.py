import os
import time
import ipaddress
import socket
import argparse

def scan_network(cidr, ports=None):
    
    network = ipaddress.ip_network(cidr, strict=False)#----------------------------------------------------------------------------------------------------------------->  Convert the CIDR input into an IP network
    
    scan_results = []
    
    for ip in network.hosts(): #---------------------------------------------------------------------------------------------------------------------------------------->  Loop through all the host IP addresses in the network
        start_time = time.time() #-------------------------------------------------------------------------------------------------------------------------------------->  Record the start time for the ping
        
        response = os.system(f"ping -c 1 -w 1 {ip} > /dev/null 2>&1")#-------------------------------------------------------------------------------------------------->  Ping the host (1 packet, 1 second timeout)
        end_time = time.time() #---------------------------------------------------------------------------------------------------------------------------------------->  Record the end time
        
        response_time = round((end_time - start_time) * 1000, 2) if response == 0 else None # -------------------------------------------------------------------------->  Calculate the round-trip time (in milliseconds) if the ping was successful
        
        status = "Up" if response == 0 else "Down" #-------------------------------------------------------------------------------------------------------------------->  Determine the status based on the response (Up or Down)
        
        if status == "Up" and ports: #---------------------------------------------------------------------------------------------------------------------------------->  If host is UP and ports are specified, scan ports
            open_ports = scan_ports(str(ip), ports)
            if open_ports: #-------------------------------------------------------------------------------------------------------------------------------------------->  If any open ports are found, include them in the results
                scan_results.append({
                    "IP": str(ip),
                    "Open Ports": open_ports
                })
        
        elif not ports: #----------------------------------------------------------------------------------------------------------------------------------------------->  If no ports are specified, return normal scan results
            error_message = "" if response == 0 else "No response" #---------------------------------------------------------------------------------------------------->  Assign error message if the host is down
            scan_results.append({
                "IP": str(ip),
                "Status": status,
                "Response Time (ms)": response_time,
                "Error Message": error_message
            })
    
    return scan_results

def scan_ports(ip, ports):
    """Scan specified ports on the given IP address."""
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1) #------------------------------------------------------------------------------------------------------------------------------------------->  Set timeout to 1 second
            if s.connect_ex((ip, port)) == 0: #------------------------------------------------------------------------------------------------------------------------->  If the connection is successful, port is open
                open_ports.append(port)
    return open_ports

def parse_ports(port_input):
    """Parse the port input format (-p flag)."""
    ports = set()
    try:
        if ',' in port_input:
            ports = {int(p) for p in port_input.split(',')} #----------------------------------------------------------------------------------------------------------->  Handle comma-separated ports
        elif '-' in port_input:
            start, end = map(int, port_input.split('-'))
            ports = set(range(start, end + 1)) #------------------------------------------------------------------------------------------------------------------------>  Handle port ranges
        else:
            ports.add(int(port_input)) #-------------------------------------------------------------------------------------------------------------------------------->  Handle single port
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid port format. Use -p 80, -p 1-100, or -p 80,443,3306")
    return sorted(ports)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner with Optional Port Scanning")
    parser.add_argument("cidr", help="Network in CIDR notation (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 80, 1-100, 22,443)", type=parse_ports, required=False)
    
    args = parser.parse_args()
    results = scan_network(args.cidr, args.ports)
    
    for device in results: #-------------------------------------------------------------------------------------------------------------------------------------------->  Print out the results
        if "Open Ports" in device:
            print(f"IP: {device['IP']}, Open Ports: {device['Open Ports']}") #------------------------------------------------------------------------------------------>  Show only open ports when -p is used
        else:
            print(f"IP: {device['IP']}, Status: {device['Status']}, Response Time: {device.get('Response Time (ms)', 'N/A')} ms, Error: {device['Error Message']}")
