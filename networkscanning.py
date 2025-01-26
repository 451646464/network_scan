from scapy.all import ARP, Ether, srp, IP, TCP, sr
import psutil
import sys
import time
from datetime import datetime
import speedtest
from tabulate import tabulate
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

def print_welcome_message():
    """Print a decorative welcome message."""
    ascii_art = pyfiglet.figlet_format("Network Scan", font="slant")
    print(Fore.CYAN + Style.BRIGHT + ascii_art)

def get_device_type(mac_address):
    """Determine device type based on MAC address."""
    vendor_lookup = {
        '00:1A': 'Apple',
        '00:1B': 'Microsoft',
        '00:1C': 'Cisco',
        '00:1D': 'Dell',
        '00:1E': 'Samsung',
    }
    for prefix in vendor_lookup:
        if mac_address.startswith(prefix):
            return vendor_lookup[prefix]
    return 'Unknown'

def get_os_type(ip):
    """Determine OS type based on TCP response."""
    packet = IP(dst=ip) / TCP(dport=80, flags='S')
    response = sr(packet, timeout=2, verbose=0)[0]
    if response:
        for sent, received in response:
            if received.haslayer(TCP):
                if received[TCP].flags == 18:  # SYN+ACK
                    if received[TCP].options:
                        for option in received[TCP].options:
                            if option[0] == 'MSS':
                                return "Linux/Unix"
                            elif option[0] == 'WScale':
                                return "Windows"
    return "Unknown"

def scan_ports(ip):
    """Scan open ports on the device."""
    open_ports = []
    for port in range(1, 1024):  # Scan ports from 1 to 1023
        packet = IP(dst=ip) / TCP(dport=port, flags='S')
        response = sr(packet, timeout=1, verbose=0)[0]
        for sent, received in response:
            if received.haslayer(TCP) and received[TCP].flags == 18:  # SYN+ACK
                open_ports.append(port)
    return open_ports

def get_network_usage(ip):
    """Get sent and received data for the device using psutil."""
    net_io = psutil.net_io_counters(pernic=True)
    data = net_io.get(ip, None)
    if data:
        return data.bytes_sent, data.bytes_recv
    return 0, 0

def measure_speed():
    """Measure download and upload speed using speedtest."""
    st = speedtest.Speedtest()
    st.download()
    st.upload()
    return st.results.download / 1_000_000, st.results.upload / 1_000_000  # Convert to Mbps

def scan_network(ip_range):
    """Scan the network to get connected devices."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        device_info = {
            'ip': received.psrc,
            'mac': received.hwsrc,
            'type': get_device_type(received.hwsrc),
            'os': get_os_type(received.psrc),
            'open_ports': scan_ports(received.psrc),
            'bytes_sent': get_network_usage(received.psrc)[0],
            'bytes_recv': get_network_usage(received.psrc)[1],
            'connection_time': str(datetime.now() - datetime.now()),  # Placeholder
            'download_speed': measure_speed()[0],
            'upload_speed': measure_speed()[1]
        }
        devices.append(device_info)
    return devices

def display_results(devices, options):
    """Display scan results based on selected options."""
    table = []
    for device in devices:
        row = []
        if 1 in options:
            row.append(device['ip'])
        if 2 in options:
            row.append(device['mac'])
        if 3 in options:
            row.append(', '.join(map(str, device['open_ports'])))
        if 4 in options:
            row.append(device['bytes_sent'])
        if 5 in options:
            row.append(device['bytes_recv'])
        if 6 in options:
            row.append(device['connection_time'])
        if 7 in options:
            row.append(f"{device['download_speed']:.2f}")
            row.append(f"{device['upload_speed']:.2f}")
        table.append(row)
    
    headers = []
    if 1 in options:
        headers.append("IP Address")
    if 2 in options:
        headers.append("MAC Address")
    if 3 in options:
        headers.append("Open Ports")
    if 4 in options:
        headers.append("Bytes Sent")
    if 5 in options:
        headers.append("Bytes Recv")
    if 6 in options:
        headers.append("Connection Time")
    if 7 in options:
        headers.append("Download Speed (Mbps)")
        headers.append("Upload Speed (Mbps)")

    print(Fore.GREEN + tabulate(table, headers, tablefmt="pretty", stralign="center"))
    print(Fore.YELLOW + "\nScan complete.")

if __name__ == "__main__":
    print_welcome_message()  # Print welcome message
    ip_range = input(Fore.MAGENTA + "Please enter the IP range to scan (e.g., 192.168.0.0/24): ")
    
    devices = scan_network(ip_range)
    print(Fore.CYAN + f"Number of connected devices: {len(devices)}")

    print(Fore.MAGENTA + "Select the information you want to display:")
    print(Fore.LIGHTYELLOW_EX + "1. Number of devices")
    print(Fore.LIGHTYELLOW_EX + "2. MAC addresses")
    print(Fore.LIGHTYELLOW_EX + "3. Open ports")
    print(Fore.LIGHTYELLOW_EX + "4. Data sent")
    print(Fore.LIGHTYELLOW_EX + "5. Data received")
    print(Fore.LIGHTYELLOW_EX + "6. Connection time")
    print(Fore.LIGHTYELLOW_EX + "7. Internet speed")
    print(Fore.LIGHTYELLOW_EX + "8. All information")

    choice = input(Fore.MAGENTA + "Enter your choice (comma-separated for multiple options, e.g., 1,2,3): ")
    options = list(map(int, choice.split(',')))

    display_results(devices, options)
