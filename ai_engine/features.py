import pandas as pd

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

def extract_features(packet):
    """
    Extract numerical features from a raw network packet.
    Only include features that match the training dataset.
    """
    features = {
        "feature1": packet["src_ip"],       # Map to feature1
        "feature2": packet["dst_ip"],       # Map to feature2
        "feature3": packet["packet_size"],  # Map to feature3
        "feature4": packet["flags"]         # Map to feature4
    }
    return pd.Series(features)