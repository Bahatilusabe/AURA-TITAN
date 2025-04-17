import tensorflow as tf
import numpy as np

# Register the custom loss function
@tf.keras.utils.register_keras_serializable()
def mse_loss(y_true, y_pred):
    mse = tf.keras.losses.MeanSquaredError()
    return mse(y_true, y_pred)

# Load models
anomaly_model = tf.keras.models.load_model("ai_engine/models/anomaly_model.h5", custom_objects={"mse_loss": mse_loss})
threat_classifier = tf.keras.models.load_model("ai_engine/models/threat_classifier.h5")

def predict_anomaly(features):
    """
    Predict if the input features are anomalous using the Autoencoder.
    """
    # Ensure features are a NumPy array
    features = np.array(features)

    # Perform reconstruction
    reconstruction = anomaly_model.predict(np.array([features]))[0]

    # Calculate Mean Squared Error (MSE)
    mse = np.mean((reconstruction - features) ** 2)
    return mse  # Higher MSE = more anomalous

def predict_threat(features):
    """
    Predict the type of threat using the FCNN.
    """
    probabilities = threat_classifier.predict(np.array([features]))[0]
    prediction = np.argmax(probabilities)
    return {"prediction": prediction, "probabilities": probabilities}

if __name__ == "__main__":
    # Test anomaly model
    try:
        print("Testing anomaly model...")
        test_features = [0.1, 0.2, 0.3, 0.4]
        anomaly_score = predict_anomaly(test_features)
        print(f"Anomaly Score: {anomaly_score}")
    except Exception as e:
        print(f"Error with anomaly model: {e}")

    # Test threat classifier
    try:
        print("Testing threat classifier...")
        test_features = [0.1, 0.2, 0.3, 0.4]
        threat = predict_threat(test_features)
        print(f"Threat Prediction: {threat}")
    except Exception as e:
        print(f"Error with threat classifier: {e}")