import sqlite3
from faulthandler import is_enabled
from scapy.all import *
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk
from threading import Thread
import requests
import json
import subprocess
import time

# Whitelisted MAC addresses
whitelist = []

# Blacklisted MAC addresses
blacklist = []

# Database setup
def setup_database():
    """
    Set up the SQLite database and create the necessary tables.
    """
    conn = sqlite3.connect('arpsentry.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  event_type TEXT, 
                  source_ip TEXT, 
                  source_mac TEXT, 
                  victim_ip TEXT, 
                  victim_mac TEXT,
                  real_mac TEXT,
                  attacker_mac TEXT,
                  interface TEXT,
                  packet_details TEXT,
                  countermeasures TEXT,
                  alert_status TEXT)''')
    conn.commit()
    conn.close()

# Function to log events to the database
def log_event(event):
    """
    Log an event to the SQLite database.

    :param dict event: The event data to log.
    """
    conn = sqlite3.connect('arpsentry.db')
    c = conn.cursor()
    c.execute('''INSERT INTO logs (timestamp, event_type, source_ip, source_mac, victim_ip, victim_mac,
                                    real_mac, attacker_mac, interface, packet_details, countermeasures, alert_status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
              (event['timestamp'], event['type'], event['source_ip'], 
               event['source_mac'], event['victim_ip'], event['victim_mac'],
               event['real_mac'], event['attacker_mac'], event['interface'],
               event['packet_details'], event['countermeasures'], event['alert_status']))
    conn.commit()
    conn.close()

# Function to fetch logs from the database
def fetch_logs():
    """
    Fetch logs from the SQLite database.

    :return: list of tuples containing log data
    """
    conn = sqlite3.connect('arpsentry.db')
    c = conn.cursor()
    c.execute('''SELECT timestamp, event_type, source_ip, source_mac, victim_ip, victim_mac,
                        real_mac, attacker_mac, interface, packet_details, countermeasures, alert_status FROM logs''')
    logs = c.fetchall()
    conn.close()
    return logs

# Function to display logs in the GUI
def display_logs():
    """
    Display logs in the logs tab.
    """
    logs = fetch_logs()
    logs_listbox.delete(0, tk.END)
    for log in logs:
        log_str = f"{log[0]} | {log[1]} | {log[2]} | {log[3]} | {log[4]} | {log[5]} | {log[6]} | {log[7]} | {log[8]} | {log[9]} | {log[10]} | {log[11]}"
        logs_listbox.insert(tk.END, log_str)

# Function to add MAC address to whitelist
def add_to_whitelist():
    """
    Add a MAC address to the whitelist.
    """
    mac = mac_entry.get()
    if mac and mac not in whitelist:
        whitelist.append(mac)
        whitelist_listbox.insert(tk.END, mac)
        mac_entry.delete(0, tk.END)

# Function to remove MAC address from whitelist
def remove_from_whitelist():
    """
    Remove a MAC address from the whitelist.
    """
    selection = whitelist_listbox.curselection()
    if selection:
        index = selection[0]
        whitelist.pop(index)
        whitelist_listbox.delete(index)

# Function to remove MAC address from blacklist
def remove_from_blacklist():
    """
    Remove a MAC address from the blacklist.
    """
    selection = blacklist_listbox.curselection()
    if selection:
        index = selection[0]
        blacklist.pop(index)
        blacklist_listbox.delete(index)

# Security tool integration settings
siem_integration_enabled = False
siem_url = "https://your-siem.example.com/api/events"
siem_auth_token = "your_auth_token"

# Function to integrate with SIEM
def integrate_with_siem(event):
    if siem_integration_enabled:
        headers = {
            "Authorization": f"Bearer {siem_auth_token}",
            "Content-Type": "application/json",
        }
        payload = json.dumps(event)
        response = requests.post(siem_url, headers=headers, data=payload)
        if response.status_code != 200:
            print(f"Failed to send event to SIEM: {response.text}")

# Function to display notifications
def show_notification(message):
    root = tk.Tk()
    root.title("ARP Spoofing Detector")
    label = tk.Label(root, text=message, font=("Arial", 16))
    label.pack(pady=10)
    root.overrideredirect(True)
    root.attributes("-alpha", 1.0)
    root.after(2000, root.destroy)
    root.mainloop()

# Function to get the MAC address of an IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

# Function to sniff packets on a specific interface
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# Function to process sniffed packets for ARP spoofing
def process_sniffed_packet(packet):
    if scapy.ARP in packet and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            interface = packet.sniffed_on

            if response_mac in whitelist:
                return

            if real_mac != response_mac:
                if response_mac not in blacklist:
                    # Block the attacker and add to blacklist
                    block_attacker(packet, real_mac)
                    notification_message = "🎉 You're safe! Blocked an attack."
                    notification_thread = Thread(
                        target=show_notification, args=(notification_message,))
                    notification_thread.start()

                    # Blacklist only the attacker's MAC address
                    blacklist.append(response_mac)
                    blacklist_listbox.insert(tk.END, response_mac)

                    # Log event
                    event = {
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
                        "type": "arp_spoofing",
                        "source_ip": packet[scapy.ARP].psrc,
                        "source_mac": packet[scapy.ARP].hwsrc,
                        "victim_ip": packet[scapy.ARP].pdst,
                        "victim_mac": packet[scapy.ARP].hwdst,
                        "real_mac": real_mac,
                        "attacker_mac": response_mac,
                        "interface": interface,
                        "packet_details": str(packet),
                        "countermeasures": "Blacklisted MAC, blocked via iptables",
                        "alert_status": "resolved"
                    }
                    log_event(event)
                    
                    # Integrate with SIEM
                    integrate_with_siem(event)

                    # Automated mitigation strategies
                    subprocess.run(["iptables", "-A", "INPUT", "-s",
                                   packet[scapy.ARP].psrc, "-j", "DROP"])
                    subprocess.run(["iptables", "-A", "OUTPUT", "-d",
                                   packet[scapy.ARP].psrc, "-j", "DROP"])

        except IndexError:
            pass

# Function to block the attacker by sending fake ARP replies
def block_attacker(packet, real_mac):
    victim_ip = packet[scapy.ARP].pdst
    gateway_ip = packet[scapy.ARP].psrc
    victim_mac = packet[scapy.ARP].hwdst
    attacker_ip = packet[ARP].psrc
    gateway_mac = real_mac

    victim_arp_reply = scapy.ARP(
        op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(victim_arp_reply, count=4, inter=0.2, verbose=False)

    # Block incoming traffic from the attacker
    subprocess.run(["sudo", "iptables", "-A", "INPUT",
                   "-s", attacker_ip, "-j", "DROP"])

    gateway_arp_reply = scapy.ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac)
    scapy.send(gateway_arp_reply, count=4, inter=0.2, verbose=False)

    # Block outgoing traffic to the attacker
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT",
                   "-d", attacker_ip, "-j", "DROP"])

    # Restore the ARP cache of the victim
    send(ARP(op=2, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff",
         psrc=attacker_ip, hwsrc=real_mac), count=5, verbose=False)

# Function to handle multiple interfaces
def handle_interfaces(interfaces):
    for interface in interfaces:
        sniff_thread = Thread(target=sniff, args=(interface,))
        sniff_thread.start()

# Setup the SQLite database
setup_database()

# GUI
root = tk.Tk()
root.title("ArpSentry")
root.geometry("700x500")
style = ttk.Style()
style.configure("TFrame", background="#f0f0f0")
style.configure("TButton", padding=6, relief="flat", background="#ccc")
style.configure("TLabel", background="#f0f0f0", font=("Helvetica", 12))
style.configure("TNotebook", background="#f0f0f0")
style.configure("TNotebook.Tab", padding=(12, 8))

# Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Whitelist tab
whitelist_tab = ttk.Frame(notebook)
notebook.add(whitelist_tab, text="Whitelist")

whitelist_label = ttk.Label(whitelist_tab, text="Whitelisted MAC addresses:")
whitelist_label.pack(pady=10)

whitelist_listbox = tk.Listbox(whitelist_tab, width=30, height=10, bd=0)
whitelist_listbox.pack(pady=5)

mac_entry = ttk.Entry(whitelist_tab, width=30)
mac_entry.pack(pady=5)

button_frame = ttk.Frame(whitelist_tab)
button_frame.pack(pady=5)

whitelist_add_button = ttk.Button(
    button_frame, text="Add to Whitelist", command=add_to_whitelist)
whitelist_add_button.grid(row=0, column=0, padx=5)

whitelist_remove_button = ttk.Button(
    button_frame, text="Remove from Whitelist", command=remove_from_whitelist)
whitelist_remove_button.grid(row=0, column=1, padx=5)

# Blacklist tab
blacklist_tab = ttk.Frame(notebook)
notebook.add(blacklist_tab, text="Blacklist")

blacklist_label = ttk.Label(blacklist_tab, text="Blacklisted MAC addresses:")
blacklist_label.pack(pady=10)

blacklist_listbox = tk.Listbox(blacklist_tab, width=30, height=10, bd=0)
blacklist_listbox.pack(pady=5)

button_frame = ttk.Frame(blacklist_tab)
button_frame.pack(pady=5)

blacklist_remove_button = ttk.Button(
    button_frame, text="Remove from Blacklist", command=remove_from_blacklist)
blacklist_remove_button.grid(row=0, column=1, padx=5)

# Logs tab
logs_tab = ttk.Frame(notebook)
notebook.add(logs_tab, text="Logs")

logs_label = ttk.Label(logs_tab, text="Event Logs:")
logs_label.pack(pady=10)

logs_listbox = tk.Listbox(logs_tab, width=80, height=15, bd=0)
logs_listbox.pack(pady=5)

fetch_logs_button = ttk.Button(logs_tab, text="Fetch Logs", command=display_logs)
fetch_logs_button.pack(pady=5)

# Interfaces list
interfaces = ["wlp2s0", "enp1s0"]

handle_interfaces(interfaces)

root.mainloop()

# Dockerfile
# FROM python:3.9-slim
# COPY . /app
# WORKDIR /app
# RUN pip install -r requirements.txt
# CMD ["python", "arpsentry.py"]

# Deploy instructions:
# 1. Build the Docker image: `docker build -t arpsentry .`
# 2. Run the container: `docker run -it --net=host arpsentry`
# Note: The `--net=host` flag is required to allow the container to access the host's network interfaces.
