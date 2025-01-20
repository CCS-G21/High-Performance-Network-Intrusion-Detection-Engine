import socket
from scapy.all import ARP, Ether, srp, sniff, IP
from threading import Thread
import time

# Known vulnerable ports
vulnerable_ports = {
    21: "FTP - Vulnerable to Brute Force",
    22: "SSH - Check for weak credentials",
    23: "Telnet - Vulnerable to interception",
    80: "HTTP - Check for outdated software",
    443: "HTTPS - Verify certificate and configurations",
    3389: "RDP - Check for unauthorized access",
}

# Suspicious traffic patterns
suspicious_patterns = {
    "unknown_source": "Packet with unknown source detected.",
    "large_packet": "Unusually large packet detected."
}

def scan_network(ip_range):
    """
    Scan the network for active devices using ARP.
    """
    print(f"[INFO] Scanning the network: {ip_range}")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = [{"ip": received.psrc, "mac": received.hwsrc} for sent, received in answered_list]
    return devices

def scan_ports(ip, ports):
    """
    Scan for open ports on a given IP address.
    """
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports

def detect_vulnerabilities(ip, open_ports):
    """
    Detect vulnerabilities based on open ports.
    """
    return [(port, vulnerable_ports[port]) for port in open_ports if port in vulnerable_ports]

def analyze_packet(packet):
    """
    Analyze a packet for suspicious activity.
    """
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_length = len(packet)

        alerts = []
        if ip_src == "0.0.0.0":
            alerts.append(suspicious_patterns["unknown_source"])
        if packet_length > 1500:
            alerts.append(suspicious_patterns["large_packet"])

        if alerts:
            print(f"\n[ALERT] Suspicious activity detected:")
            print(f"  Source: {ip_src}")
            print(f"  Destination: {ip_dst}")
            for alert in alerts:
                print(f"  {alert}")
            print("-" * 50)

def start_real_time_monitoring():
    """
    Start real-time traffic monitoring using scapy.
    """
    print("\n[INFO] Starting real-time traffic monitoring...\n")
    sniff(prn=analyze_packet, store=False)

def start_scanning(ip_range):
    """
    Main scanning function that combines network and port scanning.
    """
    print("==== Network Scan ====")
    devices = scan_network(ip_range)
    if not devices:
        print("[INFO] No active devices found on the network.")
        return

    print("Active devices detected:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

    print("\n==== Port and Vulnerability Scan ====")
    for device in devices:
        ip = device['ip']
        print(f"\nScanning {ip} for open ports...")
        open_ports = scan_ports(ip, range(1, 1025))
        if open_ports:
            print(f"  Open ports: {open_ports}")
            vulnerabilities = detect_vulnerabilities(ip, open_ports)
            if vulnerabilities:
                print(f"  Vulnerabilities detected:")
                for port, description in vulnerabilities:
                    print(f"    Port {port}: {description}")
            else:
                print("  No known vulnerabilities detected.")
        else:
            print("  No open ports detected.")
        print("-" * 40)

if __name__ == "__main__":
    target_ip_range = "192.168.1.0/24"  # Set your network range here

    # Run scanning in a separate thread
    scanning_thread = Thread(target=start_scanning, args=(target_ip_range,))
    scanning_thread.start()

    # Simultaneously run real-time traffic monitoring
    start_real_time_monitoring()
