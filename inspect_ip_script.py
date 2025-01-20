import customtkinter as ctk
import socket
import whois
from urllib.parse import urlparse
import tkinter.messagebox as msgbox  # Import messagebox from tkinter

# Load blacklisted IPs from a file
def load_blacklist():
    try:
        with open("blacklist.txt", "r") as file:
            return file.read().splitlines()
    except FileNotFoundError:
        return []

# Save blacklisted IPs to a file
def save_blacklist():
    with open("blacklist.txt", "w") as file:
        for ip in BLACKLIST_IPS:
            file.write(ip + "\n")

# Initialize the blacklist
BLACKLIST_IPS = load_blacklist()

# Function to check if a URL contains suspicious keywords
def is_suspicious(url):
    suspicious_keywords = ['login', 'secure', 'account', 'verify', 'update', 'bank', 'signin']
    for keyword in suspicious_keywords:
        if keyword in url:
            return True
    return False

# Function to perform DNS lookup and check if the domain is suspicious
def domain_info(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return str(e)

# Function to ping the server and check if it's active
def ping_server(url):
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

# Function to check if the URL is phishing or not
def check_phishing(url):
    result = ""
    server_ip = ping_server(url)
    
    # Step 1: Check for suspicious URL patterns
    result += "Checking for suspicious keywords...\n"
    if is_suspicious(url):
        result += "Suspicious URL - Contains phishing keywords.\n"
    else:
        result += "No suspicious keywords found.\n"
    
    # Step 2: Check domain information
    result += "Checking domain information...\n"
    domain_whois = domain_info(url)
    if isinstance(domain_whois, str) or not domain_whois:
        result += "Domain information not found.\n"
    else:
        result += f"Domain info found: {domain_whois}\n"

    # Step 3: Ping the server to check if it's active
    result += "Pinging the server...\n"
    if server_ip is None:
        result += "Server not reachable. Could be suspicious.\n"
    else:
        result += f"Server IP: {server_ip}\n"

        # Step 4: Check if the server IP is in the blacklist
        if server_ip in BLACKLIST_IPS:
            result += f"Warning: This IP ({server_ip}) is blacklisted! This URL is unsafe.\n"
            return result + "\nWarning: The URL is blacklisted and is unsafe!", "Warning"
    
    # Step 5: Final message based on analysis
    if "Suspicious URL" in result or "Server not reachable" in result:
        return result + "\nWarning: The URL may be a phishing attempt!", "Warning"
    else:
        return result + "\nURL seems safe.", "Success"

# Function to update the result based on user input
def check_url_action():
    url = url_entry.get()
    result, status = check_phishing(url)
    
    # Set the result label to display the results
    result_label.configure(state="normal")
    result_label.delete(1.0, ctk.END)  # Clear previous text
    result_label.insert(ctk.END, result)
    result_label.configure(state="disabled")
    
    # Show popup based on status using tkinter.messagebox
    if status == "Success":
        msgbox.showinfo("Success", "The URL seems safe.")
    else:
        msgbox.showwarning("Warning", "Warning: The URL may be a phishing attempt!")

# Function to add IP to blacklist
def add_ip_to_blacklist():
    ip = add_ip_entry.get()
    if ip and ip not in BLACKLIST_IPS:
        BLACKLIST_IPS.append(ip)
        save_blacklist()
        update_blacklist_display()

# Function to remove IP from blacklist
def remove_ip_from_blacklist():
    ip = remove_ip_entry.get()
    if ip in BLACKLIST_IPS:
        BLACKLIST_IPS.remove(ip)
        save_blacklist()
        update_blacklist_display()

# Function to update IP in blacklist
def update_ip_in_blacklist():
    old_ip = old_ip_entry.get()
    new_ip = new_ip_entry.get()
    if old_ip in BLACKLIST_IPS and new_ip:
        index = BLACKLIST_IPS.index(old_ip)
        BLACKLIST_IPS[index] = new_ip
        save_blacklist()
        update_blacklist_display()

# Function to update the blacklist display in the GUI
def update_blacklist_display():
    blacklist_display.delete(1.0, ctk.END)  # Clear the display
    for ip in BLACKLIST_IPS:
        blacklist_display.insert(ctk.END, ip + "\n")

# Create the main application window
app = ctk.CTk()

# Set window title and size
app.title("Advanced Phishing URL Detector")
app.geometry("680x680")  # Set a specific window size
app.resizable(False, False)

# Create a tab view widget
tabview = ctk.CTkTabview(app)
tabview.pack(pady=10, padx=10, fill="both", expand=True)

# Create a "Phishing Check" tab
phishing_check_tab = tabview.add("Phishing Check")

# Create a frame for phishing check
phishing_check_frame = ctk.CTkFrame(phishing_check_tab)
phishing_check_frame.grid(row=0, column=0, pady=20, padx=20, sticky="nsew")

# Configure the grid layout for the frame
phishing_check_frame.grid_rowconfigure(0, weight=1)
phishing_check_frame.grid_rowconfigure(1, weight=1)
phishing_check_frame.grid_rowconfigure(2, weight=1)
phishing_check_frame.grid_rowconfigure(3, weight=2)

# Create a label for instructions
url_label = ctk.CTkLabel(phishing_check_frame, text="Enter URL to check for phishing:")
url_label.grid(row=0, column=0, pady=10, sticky="w")

# Create an entry widget for the URL
url_entry = ctk.CTkEntry(phishing_check_frame, width=590)
url_entry.grid(row=1, column=0, pady=10, sticky="ew")

# Create a button to check the URL
check_button = ctk.CTkButton(phishing_check_frame, text="Check URL", command=check_url_action)
check_button.grid(row=2, column=0, pady=10, sticky="ew")

# Create a label for displaying results
result_label = ctk.CTkTextbox(phishing_check_frame, width=590, height=400)
result_label.grid(row=3, column=0, pady=10, sticky="nsew")
result_label.configure(state="disabled")  # Make the text box read-only initially

# Create a "Blacklist Management" tab
blacklist_management_tab = tabview.add("Blacklist Management")

# Create a frame for blacklist management
blacklist_frame = ctk.CTkFrame(blacklist_management_tab)
blacklist_frame.grid(row=0, column=0, pady=20, padx=20, sticky="nsew")

# Configure grid layout for the frame
blacklist_frame.grid_rowconfigure(0, weight=1)
blacklist_frame.grid_rowconfigure(1, weight=1)
blacklist_frame.grid_rowconfigure(2, weight=1)
blacklist_frame.grid_rowconfigure(3, weight=2)

# Add IP to blacklist
add_ip_label = ctk.CTkLabel(blacklist_frame, text="Add IP to Blacklist:")
add_ip_label.grid(row=0, column=0, pady=5, sticky="w")
add_ip_entry = ctk.CTkEntry(blacklist_frame, width=400)
add_ip_entry.grid(row=1, column=0, pady=5, sticky="ew")
add_ip_button = ctk.CTkButton(blacklist_frame, text="Add IP", command=add_ip_to_blacklist)
add_ip_button.grid(row=2, column=0, pady=10, sticky="ew")

# Remove IP from blacklist
remove_ip_label = ctk.CTkLabel(blacklist_frame, text="Remove IP from Blacklist:")
remove_ip_label.grid(row=3, column=0, pady=5, sticky="w")
remove_ip_entry = ctk.CTkEntry(blacklist_frame, width=400)
remove_ip_entry.grid(row=4, column=0, pady=5, sticky="ew")
remove_ip_button = ctk.CTkButton(blacklist_frame, text="Remove IP", command=remove_ip_from_blacklist)
remove_ip_button.grid(row=5, column=0, pady=10, sticky="ew")

# Update IP in blacklist
old_ip_label = ctk.CTkLabel(blacklist_frame, text="Update IP in Blacklist (Old -> New):")
old_ip_label.grid(row=6, column=0, pady=5, sticky="w")
old_ip_entry = ctk.CTkEntry(blacklist_frame, width=200)
old_ip_entry.grid(row=7, column=0, pady=5, sticky="w")
new_ip_entry = ctk.CTkEntry(blacklist_frame, width=200)
new_ip_entry.grid(row=7, column=1, pady=5, sticky="w")
update_ip_button = ctk.CTkButton(blacklist_frame, text="Update IP", command=update_ip_in_blacklist)
update_ip_button.grid(row=8, column=0, columnspan=2, pady=10, sticky="ew")

# Display Blacklist IPs
blacklist_label = ctk.CTkLabel(blacklist_frame, text="Current Blacklist:")
blacklist_label.grid(row=9, column=0, pady=10, sticky="w")
blacklist_display = ctk.CTkTextbox(blacklist_frame, width=400, height=150)
blacklist_display.grid(row=10, column=0, pady=10, columnspan=2, sticky="nsew")
update_blacklist_display()

# Run the application
app.mainloop()
