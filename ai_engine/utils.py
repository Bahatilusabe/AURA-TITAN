import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def log_event(event_type, details):
    """
    Log an event for forensic analysis.
    """
    logging.info(f"{event_type}: {details}")

def set_threshold(model_type, value):
    """
    Set thresholds for anomaly detection or classification.
    """
    print(f"Setting {model_type} threshold to {value}")