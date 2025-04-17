def block_ip(ip_address):
    """
    Block an IP address using the firewall.
    """
    print(f"Blocking IP: {ip_address}")
    # Example: Use iptables or a firewall API
    # os.system(f"iptables -A INPUT -s {ip_address} -j DROP")

def send_alert(threat_details):
    """
    Send an alert to the SOC dashboard or admin.
    """
    print(f"ALERT: {threat_details}")
    # Example: Send an email, push notification, or log the alert