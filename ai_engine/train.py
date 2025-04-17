import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import tensorflow as tf
from tensorflow.keras import layers, models

# Ensure the models directory exists
os.makedirs("ai_engine/models", exist_ok=True)

# Register the loss function
@tf.keras.utils.register_keras_serializable()
def mse_loss(y_true, y_pred):
    mse = tf.keras.losses.MeanSquaredError()
    return mse(y_true, y_pred)

def train_anomaly_model(data_path, save_path="ai_engine/models/anomaly_model.h5"):
    """
    Train an Autoencoder for anomaly detection.
    """
    data = pd.read_csv(data_path).values  # Convert to NumPy array

    # Define the Autoencoder
    model = models.Sequential([
        layers.Input(shape=(data.shape[1],)),
        layers.Dense(16, activation="relu"),
        layers.Dense(8, activation="relu"),
        layers.Dense(16, activation="relu"),
        layers.Dense(data.shape[1], activation="sigmoid")
    ])

    model.compile(optimizer="adam", loss=mse_loss)  # Use the registered loss function
    model.fit(data, data, epochs=50, batch_size=32, validation_split=0.2)
    model.save(save_path)  # Save the model in .h5 format
    print(f"Anomaly model saved to {save_path}")

def train_classifier_model(data_path, save_path="ai_engine/models/threat_classifier.h5"):
    """
    Train a Fully Connected Neural Network for threat classification.
    """
    data = pd.read_csv(data_path)
    X = data.drop("label", axis=1).values
    y = pd.get_dummies(data["label"]).values  # One-hot encode labels

    # Define the FCNN
    model = models.Sequential([
        layers.Input(shape=(X.shape[1],)),
        layers.Dense(64, activation="relu"),
        layers.Dense(32, activation="relu"),
        layers.Dense(y.shape[1], activation="softmax")
    ])

    model.compile(optimizer="adam", loss="categorical_crossentropy", metrics=["accuracy"])
    model.fit(X, y, epochs=50, batch_size=32, validation_split=0.2)
    model.save(save_path)  # Save the model in .h5 format
    print(f"Threat classifier model saved to {save_path}")

def analyze_reconstruction_errors(data_path):
    """
    Analyze reconstruction errors for anomaly detection.
    """
    data = pd.read_csv(data_path)
    model = joblib.load("ai_engine/models/anomaly_model.pkl")
    errors = model.decision_function(data)
    print(f"Reconstruction errors: {errors}")

# Train the models
train_anomaly_model("data/anomaly_data.csv", save_path="ai_engine/models/anomaly_model.h5")
train_classifier_model("data/threat_data.csv", save_path="ai_engine/models/threat_classifier.h5")

# Analyze reconstruction errors
analyze_reconstruction_errors("data/anomaly_data.csv")