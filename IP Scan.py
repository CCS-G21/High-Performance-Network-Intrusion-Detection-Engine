from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    print(f"Scanning the network: {ip_range}\n")
    
    # Create an ARP request
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and receive responses
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    # Parse and display the results
    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def display_results(devices):
    print("Active devices on the network:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    # Example: Replace '192.168.0.1/24' with your network's IP range
    target_ip_range = "172.17.25.155/65"
    
    active_devices = scan_network(target_ip_range)
    if active_devices:
        display_results(active_devices)
    else:
        print("No devices found on the network.")
