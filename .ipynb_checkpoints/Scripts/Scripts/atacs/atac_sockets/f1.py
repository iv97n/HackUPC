import socket
import threading

# Define target IP and port
target_ip = "127.20.10.11"
target_port = 80

# Number of threads (representing "people")
num_threads = 10

# Number of packets to send per thread
packets_per_thread = 100

def send_packets():
    # Create TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the target
    tcp_socket.connect((target_ip, target_port))
    
    # Send packets
    for _ in range(packets_per_thread):
        tcp_socket.sendall(b"Hello, world!")
    
    # Close the socket
    tcp_socket.close()

# Create and start threads
threads = []
for _ in range(num_threads):
    thread = threading.Thread(target=send_packets)
    thread.start()
    threads.append(thread)

# Wait for all threads to finish
for thread in threads:
    thread.join()
