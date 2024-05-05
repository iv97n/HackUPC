
from scapy.all import sniff

def packet_handler(packet):
    # Print the full details of the packet
    print(packet.show())

# Replace 'wlo1' with the name of the interface you want to listen on
interface = 'Wi-Fi'

bpf_filter = 'ip or ip6'
# Start sniffing packets on the specified interface with the specified BPF filter
print(f"Sniffing incoming packets on interface {interface}...")
sniff(iface=interface, prn=packet_handler, filter=bpf_filter, store=False)



