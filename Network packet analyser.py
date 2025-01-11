from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def analyze_packet(packet):
    """
    Function to analyze and display packet details.
    """
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")

        # Further analyze if it's a TCP packet
        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Source Port: {tcp_sport}, TCP Destination Port: {tcp_dport}")

        # Further analyze if it's a UDP packet
        elif packet.haslayer(UDP):
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"UDP Source Port: {udp_sport}, UDP Destination Port: {udp_dport}")

        # Show payload data (if available)
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load
            print(f"Payload (Raw Data): {raw_data}")

    print("-" * 50)

def start_sniffing(interface="eth0"):
    """
    Start sniffing packets on the specified network interface.
    """
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=analyze_packet, store=0)

if __name__ == "__main__":
    # Change the interface name as needed
    interface = input("Enter the network interface to sniff on (e.g., eth0 or wlan0): ")
    start_sniffing(interface)
