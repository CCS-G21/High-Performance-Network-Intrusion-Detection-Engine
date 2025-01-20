import time
import random

# Cyclogram stages
def initialize_system():
    print("[1] Initializing Intrusion Detection Engine...")
    time.sleep(1)
    print("[2] Loading detection rules and patterns...\n")
    time.sleep(1)

def capture_network_traffic():
    print("[3] Capturing network traffic...")
    # Simulate network packets
    packets = [
        {"source": "192.168.0.10", "destination": "192.168.0.1", "port": 80, "size": 500},
        {"source": "192.168.0.15", "destination": "192.168.0.1", "port": 22, "size": 1500},
        {"source": "unknown", "destination": "192.168.0.1", "port": 443, "size": 8000},  # Suspicious
    ]
    time.sleep(1)
    print(f"[4] Captured {len(packets)} packets.\n")
    return packets

def analyze_traffic(packets):
    print("[5] Analyzing network traffic...")
    alerts = []
    for packet in packets:
        if packet["source"] == "unknown" or packet["size"] > 1000:  # Example anomaly detection rule
            alerts.append(f"Alert: Suspicious activity detected from {packet['source']}!")
        time.sleep(0.5)
    print("[6] Analysis completed.\n")
    return alerts

def respond_to_threat(alerts):
    if alerts:
        print("[7] Threat detected! Responding...\n")
        for alert in alerts:
            print(alert)
        print("\n[8] Blocking malicious IPs and generating a detailed report...\n")
    else:
        print("[7] No threats detected. Network is secure.\n")

def main():
    print("==== Intrusion Detection Engine Cyclogram ====\n")
    initialize_system()
    packets = capture_network_traffic()
    alerts = analyze_traffic(packets)
    respond_to_threat(alerts)
    print("==== Monitoring Complete ====")

if __name__ == "__main__":
    main()
