import logging
import pandas as pd
import csv
from sklearn.ensemble import IsolationForest
from ai_engine.predict import predict_anomaly, predict_threat
from ai_engine.data_collector import collect_traffic
from ai_engine.features import extract_features
from ai_engine.threat_response import block_ip, send_alert
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler("ai_engine/logs/monitor.log"),
        logging.StreamHandler()
    ]
)

def train_anomaly_model(data_path, save_path="ai_engine/models/anomaly_model.pkl"):
    """
    Train an Isolation Forest model for anomaly detection.
    """
    data = pd.read_csv(data_path)
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(data)
    joblib.dump(model, save_path)

def save_event(event_type, packet):
    """
    Save detected events (anomalies or threats) to a CSV file.
    """
    with open("ai_engine/logs/detected_events.csv", mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([event_type, packet])

def monitor_traffic():
    """
    Continuously monitor traffic, detect threats, and trigger responses.
    """
    print("Starting real-time traffic monitoring...")
    while True:
        packets = collect_traffic(count=50)  # Increase batch size
        features_batch = [extract_features(packet) for packet in packets]

        # Anomaly detection
        anomaly_scores = [predict_anomaly(features) for features in features_batch]
        for i, score in enumerate(anomaly_scores):
            if score > 0.01:  # Adjust threshold based on training
                logging.info(f"Anomaly detected: {packets[i]}")
                save_event("anomaly", packets[i])
                send_alert({"type": "anomaly", "details": packets[i]})
                continue

        # Threat classification
        threats = [predict_threat(features) for features in features_batch]
        for i, threat in enumerate(threats):
            if threat["prediction"] != "normal":
                logging.info(f"Threat detected: {threat}")
                save_event("threat", packets[i])
                block_ip(packets[i]["src_ip"])

if __name__ == "__main__":
    monitor_traffic()