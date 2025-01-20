import tkinter as tk
from tkinter import ttk, messagebox  # Import messagebox from tkinter
import customtkinter as ctk
from scapy.all import sniff, IP, TCP
from threading import Thread, Event
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from win10toast import ToastNotifier  # Add this at the top
import ipaddress  # Add this at the top for subnet masking
import subprocess  # Import subprocess to run another Python file
import mysql.connector  # MySQL connector import

# Initialize the application
ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Correct usage

root = ctk.CTk()
root.title("Network Monitor")
root.geometry("800x600")

# Modify the port_data dictionary to include protocols
port_data = defaultdict(lambda: {"traffic": 0, "status": "Safe", "ips": set(), "subnet_mask": "Unknown", "protocols": set()})
traffic_stats = {"inbound": [], "outbound": []}
monitoring = Event()
status_text = ctk.StringVar(value="Offline")

# Create a ToastNotifier instance
toaster = ToastNotifier()

# Database connection setup
def connect_to_db():
    try:
        # Replace these with your actual MySQL database details
        db_connection = mysql.connector.connect(
            host="localhost",
            user="root",  # MySQL username
            password="2003",  # MySQL password
            database="network_monitor_db"  # Your database name | CREATE DATABASE network_monitor_db;
        )
        return db_connection
    except mysql.connector.Error as err:
        messagebox.showerror("Database Connection Error", str(err))
        return None

# Create the table if it doesn't exist
def create_table_if_not_exists(db_connection):
    cursor = db_connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_data (
            id INT AUTO_INCREMENT PRIMARY KEY,
            port INT NOT NULL,
            status VARCHAR(255),
            traffic BIGINT,
            associated_ips TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db_connection.commit()
    cursor.close()

def process_packet(packet):
    if IP in packet:
        dst_port = packet[TCP].dport if TCP in packet else None  # Capture only TCP ports if available
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.proto  # This will capture the protocol number (e.g., 6 for TCP, 17 for UDP)

        # Convert protocol number to protocol name (e.g., TCP, UDP, ICMP)
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = f"Unknown Protocol ({protocol})"

        # Update traffic stats
        if src_ip == "127.0.0.1":
            traffic_stats["inbound"].append(len(packet))
        else:
            traffic_stats["outbound"].append(len(packet))

        # Update port data with protocol and other details
        if dst_port:
            port_data[dst_port]["traffic"] += len(packet)
            port_data[dst_port]["status"] = "Vulnerable" if dst_port < 1024 else "Safe"
            port_data[dst_port]["ips"].update([src_ip, dst_ip])
            port_data[dst_port]["protocols"].add(protocol_name)  # Store the protocol information

        # Check for vulnerabilities and send notifications
        if port_data[dst_port]["status"] == "Vulnerable":
            try:
                network = ipaddress.ip_network(src_ip, strict=False)
                subnet_mask = network.netmask
            except ValueError:
                subnet_mask = "Unknown"

            # Store subnet mask in port data
            port_data[dst_port]["subnet_mask"] = subnet_mask

            # Create notification message
            notification_message = (
                f"Vulnerability detected on Port {dst_port}!\n"
                f"Source IP: {src_ip}\n"
                f"Destination IP: {dst_ip}\n"
                f"Subnet Mask: {subnet_mask}\n"
                f"Protocol: {protocol_name}"
            )

            # Display Windows notification
            toaster.show_toast(
                "Network Monitor Alert",
                notification_message,
                duration=10,
                threaded=True
            )

# Start sniffing in a separate thread
def start_sniffing():
    while monitoring.is_set():
        try:
            sniff(prn=process_packet, store=False, timeout=1)
        except Exception as e:
            print(f"Error while sniffing: {e}")
            monitoring.clear()  # Stop monitoring if sniffing fails

# Start/Stop monitoring
def toggle_monitoring():
    if monitoring.is_set():
        monitoring.clear()
        status_text.set("Offline")
    else:
        monitoring.set()
        status_text.set("Online")
        sniff_thread = Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()

# Export table data to MySQL
def export_to_mysql():
    db_connection = connect_to_db()
    if db_connection is None:
        return  # Exit if DB connection fails

    create_table_if_not_exists(db_connection)

    cursor = db_connection.cursor()

    # Insert data into the database
    for port, data in port_data.items():
        try:
            cursor.execute("""
                INSERT INTO port_data (port, status, traffic, associated_ips)
                VALUES (%s, %s, %s, %s);
            """, (port, data["status"], data["traffic"], ", ".join(data["ips"])))
        except mysql.connector.Error as err:
            print(f"Error inserting data for port {port}: {err}")
            continue

    db_connection.commit()
    cursor.close()
    db_connection.close()

    messagebox.showinfo("Export Successful", "Data successfully exported to MySQL database.")

# Inspect IP function - runs another Python script
def inspect_ip():
    try:
        # Use subprocess to run another Python file (replace 'inspect_ip_script.py' with the actual filename)
        subprocess.run(["python", "inspect_ip_script.py"], check=True)
        messagebox.showinfo("Inspect IP", "Inspect IP script executed successfully.")  # Use tkinter's messagebox
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Inspect IP", f"Error running Inspect IP script: {e}")  # Use tkinter's messagebox

def show_port_details(event):
    selected_item = table.selection()
    if not selected_item:
        messagebox.showerror("Error", "No row selected!")  # Use tkinter's messagebox
        return

    selected_values = table.item(selected_item, "values")
    port = int(selected_values[0])
    data = port_data[port]

    # Create the detail text to show the protocol details, subnet mask, and associated IPs
    protocol_list = ", ".join(data["protocols"])  # List all protocols
    detail_text = (
        f"Port: {port}\n"
        f"Vulnerability Status: {data['status']}\n"
        f"Traffic: {data['traffic'] / (1024**3):.6f} GBps\n"  # Show traffic in GBps
        f"Subnet Mask: {data['subnet_mask']}\n"  # Show the subnet mask
        f"Associated IPs: {', '.join(data['ips'])}\n"  # Show associated IPs
        f"Protocols: {protocol_list}"  # Show the list of protocols
    )
    messagebox.showinfo("Port Details", detail_text)  # Use tkinter's messagebox

# Update the GUI table
def update_table():
    table.delete(*table.get_children())
    for port, data in port_data.items():
        # Convert traffic to GBps
        traffic_gbps = data["traffic"] / (1024**3)  # Traffic in GBps
        traffic_str = f"{traffic_gbps:.6f} GBps"  # Format traffic as GBps
        
        # Insert row with conditional coloring for Vulnerable ports
        if data["status"] == "Vulnerable":
            table.insert("", "end", values=(port, data["status"], traffic_str), tags=("vulnerable",))
        else:
            table.insert("", "end", values=(port, data["status"], traffic_str))

    root.after(1000, update_table)

# Update the graph
def update_graph():
    inbound = sum(traffic_stats["inbound"])
    outbound = sum(traffic_stats["outbound"])

    traffic_stats["inbound"].clear()
    traffic_stats["outbound"].clear()

    # Update the line chart
    x_data.append(time.time())
    inbound_data.append(inbound)
    outbound_data.append(outbound)

    line1.set_data(x_data, inbound_data)
    line2.set_data(x_data, outbound_data)
    ax.relim()
    ax.autoscale_view()

    canvas.draw_idle()
    root.after(1000, update_graph)

# Table for displaying port data
columns = ("Port", "Vulnerability Status", "Traffic (GBps)")
table_frame = ctk.CTkFrame(root)
table_frame.pack(side="top", fill="both", expand=True, padx=10, pady=10)

# Create a Treeview widget using tkinter.ttk
table = ttk.Treeview(table_frame, columns=columns, show="headings", height=10)

# Set up the headings
table.heading("Port", text="Port")
table.heading("Vulnerability Status", text="Vulnerability Status")
table.heading("Traffic (GBps)", text="Traffic (GBps)")

# Set the column alignment
table.column("Port", anchor="center")
table.column("Vulnerability Status", anchor="center")
table.column("Traffic (GBps)", anchor="center")

# Add the table to the frame
table.pack(side="top", fill="both", expand=True)

# Bind double-click event to show port details
table.bind("<Double-1>", show_port_details)

# Apply tag color styling for vulnerable ports
table.tag_configure("vulnerable", foreground="red")

# Control Buttons
controls_frame = ctk.CTkFrame(root)
controls_frame.pack(side="top", fill="x", padx=10, pady=5)

start_stop_button = ctk.CTkButton(controls_frame, text="Start/Stop Monitoring", command=toggle_monitoring)
start_stop_button.pack(side="left", padx=5, pady=5)

export_button = ctk.CTkButton(controls_frame, text="Export to MySQL", command=export_to_mysql)  # Update button text
export_button.pack(side="left", padx=5, pady=5)

inspect_button = ctk.CTkButton(controls_frame, text="Inspect IP", command=inspect_ip)  # Add the Inspect IP button
inspect_button.pack(side="left", padx=5, pady=5)

# Status Bar
status_frame = ctk.CTkFrame(root)
status_frame.pack(side="bottom", fill="x", padx=10, pady=5)

status_label = ctk.CTkLabel(status_frame, text="Status:")
status_label.pack(side="left", padx=5)

status_display = ctk.CTkLabel(status_frame, textvariable=status_text)
status_display.pack(side="left", padx=5)

# Real-time graph
fig, ax = plt.subplots(figsize=(6, 4))
ax.set_title("Inbound vs Outbound Traffic")
ax.set_xlabel("Time")
ax.set_ylabel("Traffic (bytes)")
x_data, inbound_data, outbound_data = [], [], []
line1, = ax.plot([], [], label="Inbound", color="blue")
line2, = ax.plot([], [], label="Outbound", color="green")
ax.legend()

canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(side="bottom", fill="both", expand=True)

# Start GUI updates
root.after(1000, update_table)
root.after(1000, update_graph)

root.mainloop()
