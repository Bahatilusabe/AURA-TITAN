from scapy.all import sniff

def collect_traffic(interface="eth0", count=10):
    """
    Simulate live network traffic for testing purposes.
    """
    parsed_packets = []
    for i in range(count):
        parsed_packets.append({
            # Convert IPs to numerical representations (e.g., last octet)
            "src_ip": i,  # Simulate numerical representation of IP
            "dst_ip": 1,  # Simulate numerical representation of IP
            "src_port": 1000 + i,
            "dst_port": 80,
            "protocol": 6,  # TCP protocol number
            "packet_size": 512,
            "flags": 2  # SYN flag
        })
    return parsed_packets