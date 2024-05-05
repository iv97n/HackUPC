import tkinter as tk
from tkinter import ttk
import threading
import time
from scapy.all import *
import pickle
from ScipyKMedoidsClustering import ScipyKMedoidsClustering  # Assuming this is the file containing your class definition
import pandas as pd
import numpy as np
from sklearn_extra.cluster import KMedoids
from sklearn.metrics import DistanceMetric
from sklearn.preprocessing import MinMaxScaler

from gower import gower_matrix


# Global variables
WINDOW_SIZE = 5  # Window size in seconds
stop_flag = False  # Flag to indicate whether to stop the main loop
lock = threading.Lock()  # Lock for thread-safe access to packets list
packets = []  # List to store packets in each window

def approximate_packet_length(length):
    return round(length / 20) * 20


# Load the trained clustering model from the .pickle file
with open('input.pickle', 'rb') as f:
   clustering_model = pickle.load(f)



print(type(clustering_model))
# Function to detect anomalies using the clustering model
def detect_anomalies(data):
    anomalies = []
    for packet in data:
        is_anomaly = clustering_model.discriminate(packet)
        if is_anomaly:
            anomalies.append(packet)
    return anomalies

# Function to process pac

# Function to process packets in a window
def process_window(window_packets):
    unique_rows = {}
    for packet in window_packets:
        row = tuple(sorted(packet.items()))  # Convert packet dictionary to a tuple for hashing
        unique_rows[row] = unique_rows.get(row, 0) + 1  # Increment count for the row

    headers = ["dport", "flags_tcp",  "len", "proto", "sport", "src", "version", "count"]
    data = []
    for row, count in unique_rows.items():
        row_with_count = dict(row)
        row_with_count['count'] = count
        row_data = [row_with_count.get(header, "") for header in headers]
        data.append(row_data)

    return headers, data

# Function to handle incoming packets
def packet_handler(packet):
    len_field = 0
    if packet.haslayer('IP'):
        len_field = getattr(packet.getlayer('IP'), 'len', 0)
    elif packet.haslayer('IPv6'):
        len_field = getattr(packet.getlayer('IPv6'), 'plen', 0)

    approximated_len = approximate_packet_length(len_field)
    packet_info = {
        'dport': getattr(packet.getlayer('TCP'), 'dport', 0) if packet.haslayer('TCP') else \
                            getattr(packet.getlayer('UDP'), 'dport', 0) if packet.haslayer('UDP') else 0,
        'flags tcp': getattr(packet.getlayer('TCP'), 'flags', 0) if packet.haslayer('TCP') else 'n',
        'len': approximated_len,
        'proto': getattr(packet.getlayer('IP'), 'proto', 0) if packet.haslayer('IP') else \
                    getattr(packet.getlayer('IPv6'), 'nh', 0) if packet.haslayer('IPv6') else 0,
        'sport': getattr(packet.getlayer('TCP'), 'sport', 0) if packet.haslayer('TCP') else \
            getattr(packet.getlayer('UDP'), 'sport', 0) if packet.haslayer('UDP') else 0,
        'src': packet.src,
        'version': getattr(packet.getlayer('IP'), 'version', 0) if packet.haslayer('IP') else 6,
    }
    with lock:
        packets.append(packet_info)

# Function to capture packets for a given duration
def capture_packets(duration):
    interface_mac_address = '5C-BA-EF-1A-D3-9D'

    # Define BPF filter to capture only incoming packets
    bpf_filter = f'ether dst {interface_mac_address}'
    start_time = time.time()
    while time.time() - start_time < duration:
        sniff(count=20000, timeout=1, prn=packet_handler, filter=bpf_filter, iface='Wi-Fi', store=True)

# Function to capture packets and process windows
def capture_and_process():
    global stop_flag

    while not stop_flag:
        start_time = time.time()
        capture_packets(WINDOW_SIZE)
        with lock:
            headers, data = process_window(packets)
            packet_dict_list = []
            for packet_data in data:
                packet_dict = {}
                for header, value in zip(headers, packet_data):
                    packet_dict[header] = value
                packet_dict_list.append(packet_dict)
            anomalies = detect_anomalies(packet_dict_list)
            #print(anomalies)

            update_treeview(headers, data, anomalies)
            packets.clear()
        elapsed_time = time.time() - start_time
        time.sleep(max(0, WINDOW_SIZE - elapsed_time))  # Wait for the remaining time in the window

# Function to update the Treeview with the latest packet information
# Function to update the Treeview with the latest packet information
def update_treeview(headers, data, anomalies):
    #tree.delete(*tree.get_children())
    for row in data:
        row_id = tree.insert("", "end", values=row)  # Insert only the first 6 values (excluding the 'Count' column)
        protocol = row[3]  # Protocol is at index 5
        if protocol in protocol_colors:
            tree.item(row_id, tags=(protocol,))

    
    for anomaly in anomalies:
        for row_id in tree.get_children():
            values = tree.item(row_id, 'values')
            if values:
                anomaly_values = list(anomaly.values())
                anomaly_values[0] =str(anomaly_values[0])  # Convert 'dport' to int
                anomaly_values[2] = str(anomaly_values[2])  # Convert 'len' to int
                anomaly_values[3] = str(anomaly_values[3])  # Convert 'proto' to int
                anomaly_values[4] = str(anomaly_values[4])  # Convert 'sport' to int
                anomaly_values[6] = str(anomaly_values[6])  # Convert 'version' to int
                if values[:7] == tuple(anomaly_values)[:7]:
                        tree.item(row_id, tags=('anomaly',))
                        break  # Break after finding the first occurrence to avoid duplicates
        
    # Configure tag for anomaly color (red)
    tree.tag_configure('anomaly', background='red')
    
    # Check if separator exists before inserting
    separator_id = f"separator_{len(data)}"  # Unique identifier for the separator
    if not tree.exists(separator_id):
        tree.insert("", "end", separator_id, text="", tags=("separator",))
        tree.tag_configure("separator", background="black")

# Create Tkinter window
root = tk.Tk()
root.title("Packet Information")

# Create Treeview widget
tree = ttk.Treeview(root)

tree["columns"] = ("1", "2", "3", "4", "5", "6", "7", "8")
tree.pack(fill="both", expand=True)

# Set column headings
#tree.heading("#0", text="Packet Info", anchor="w")
for idx, header in enumerate(["dport", "flags_tcp",  "len", "proto", "sport", "src", "version", "count"], start=1):
    tree.heading(f"#{idx}", text=header, anchor="w")

# Define colors for different protocols
protocol_colors = {
    1 : "orange",
    6 : "lightgreen",
    17 : "lightblue",
    # Add more protocols and colors as needed
}

# Apply tag configuration for protocol colors
for protocol, color in protocol_colors.items():
    tree.tag_configure(protocol, background=color)

# Start capturing and processing packets in a separate thread
capture_thread = threading.Thread(target=capture_and_process)
capture_thread.start()

def on_key_press(event):
    if event.char == 'a':
        # Create a simulated packet
        simulated_packet = {
            'dport': 5678,
            'flags_tcp': '',
            'len': 160,
            'proto': 6,  # TCP
            'sport': 1234,
            'src': '00:bf:77:b9:23:fb',
            'version': 4,
        }
        with lock:
            for _ in range(473):
                packets.append(simulated_packet)
    # Simulate different scenarios for other keys
    elif event.char == 'b':
        # Create a simulated packet with unusual port number
        simulated_packet = {
            'dport': 9999,  # Unusual port number
            'flags_tcp': '',
            'len': 200,
            'proto': 6,  # TCP
            'sport': 4321,
            'src': '00:bf:77:b9:23:fb',
            'version': 4,
        }
        with lock:
            packets.append(simulated_packet)
    
    elif event.char == 'c':
        # Create a simulated packet with large length
        simulated_packet = {
            'dport': 80,
            'flags_tcp': '',
            'len': 5000,  # Large length
            'proto': 6,  # TCP
            'sport': 9876,
            'src': '00:bf:77:b9:23:fb',
            'version': 4,
        }
        with lock:
            packets.append(simulated_packet)
    elif event.char == 'd':
        # Create a simulated packet with random values
        simulated_packet = {
            'dport': random.randint(1024, 65535),  # Random port number
            'flags_tcp': '',  # Random TCP flag
            'len': random.randint(50, 1000),  # Random length
            'proto': random.choice([6, 17]),  # Random protocol (TCP or UDP)
            'sport': random.randint(1024, 65535),  # Random source port
            'src': '00:bf:77:b9:23:fb',
            'version': random.choice([4, 6]),  # Random IP version
        }
        with lock:
            packets.append(simulated_packet)

# Bind the 'a' key press event to the on_key_press function
root.bind('<KeyPress-a>', on_key_press)
root.bind('<KeyPress-b>', on_key_press)
root.bind('<KeyPress-c>', on_key_press)
root.bind('<KeyPress-d>', on_key_press)


# Start Tkinter main loop
root.mainloop()
