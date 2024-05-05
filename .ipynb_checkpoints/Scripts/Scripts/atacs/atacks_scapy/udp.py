import threading
from scapy.all import *

# Define target IP and port
target_ip = "127.0.0.1"
target_port = 80  # Puerto UDP de destino

# Number of threads (representing "people")
num_threads = 10

# Number of packets to send per thread
packets_per_thread = 100

def send_packets():
    # Craft UDP packet
    udp_packet = IP(dst=target_ip)/UDP(dport=target_port)
    
    # Send packets
    for _ in range(packets_per_thread):
        send(udp_packet)

# Create and start threads
threads = []
for _ in range(num_threads):
    thread = threading.Thread(target=send_packets)
    thread.start()
    threads.append(thread)

# Wait for all threads to finish
for thread in threads:
    thread.join()
