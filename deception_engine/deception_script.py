import logging
import random
import socket
import os
import threading

# Ensure the logs directory exists
os.makedirs("deception_engine/logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler("deception_engine/logs/deception.log"),
        logging.StreamHandler()
    ]
)

def generate_fake_data():
    """
    Generate fake data to mislead attackers.
    """
    fake_data = {
        "username": f"user{random.randint(1000, 9999)}",
        "password": f"pass{random.randint(1000, 9999)}",
        "ip_address": f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}",
        "login_time": f"{random.randint(0, 23)}:{random.randint(0, 59)}:{random.randint(0, 59)}",
        "file_accessed": f"/var/log/{random.choice(['auth.log', 'syslog', 'kern.log'])}"
    }
    logging.info(f"Generated fake data: {fake_data}")
    return fake_data

def simulate_honeypot():
    """
    Simulate a honeypot to attract attackers.
    """
    logging.info("Honeypot service starting...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", 9090))
            server.listen(5)
            logging.info("Honeypot service successfully started on port 9090. Waiting for connections...")
            while True:
                client, address = server.accept()
                logging.info(f"Connection from {address}")
                client.sendall(b"Welcome to the honeypot!\n")
                client.close()
    except Exception as e:
        logging.error(f"Error starting honeypot: {e}")

def simulate_http_honeypot():
    """
    Simulate a fake HTTP server to attract attackers.
    """
    logging.info("HTTP Honeypot service starting...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", 8080))  # HTTP honeypot on port 8080
            server.listen(5)
            logging.info("HTTP Honeypot service successfully started on port 8080. Waiting for connections...")
            while True:
                client, address = server.accept()
                logging.info(f"HTTP connection from {address}")
                http_response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "\r\n"
                    "<html><body><h1>Welcome to the fake HTTP server!</h1></body></html>\r\n"
                )
                client.sendall(http_response.encode())
                client.close()
    except Exception as e:
        logging.error(f"Error starting HTTP honeypot: {e}")

if __name__ == "__main__":
    # Example usage
    generate_fake_data()

    # Run honeypots in parallel
    tcp_thread = threading.Thread(target=simulate_honeypot)
    http_thread = threading.Thread(target=simulate_http_honeypot)

    tcp_thread.start()
    http_thread.start()

    tcp_thread.join()
    http_thread.join()