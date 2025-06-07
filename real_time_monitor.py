import time
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import joblib
import smtplib
from email.mime.text import MIMEText

class RealTimeThreatMonitor:
    def __init__(self, model_path='models/anomaly_autoencoder.h5', scaler_path='models/scaler.save', alert_email=None):
        self.model = load_model(model_path)
        self.scaler = joblib.load(scaler_path)
        self.alert_email = alert_email

    def preprocess(self, data):
        X = data.values
        X_scaled = self.scaler.transform(X)
        return X_scaled

    def detect_anomalies(self, X_scaled):
        X_pred = self.model.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - X_pred, 2), axis=1)
        threshold = np.percentile(mse, 95)  # Use same threshold as training
        anomalies = mse > threshold
        return anomalies, mse

    def send_alert(self, message):
        if not self.alert_email:
            print("Alert: ", message)
            return
        # Example email alert (configure SMTP server accordingly)
        msg = MIMEText(message)
        msg['Subject'] = 'Cybersecurity Threat Alert'
        msg['From'] = 'alert@yourdomain.com'
        msg['To'] = self.alert_email
        try:
            with smtplib.SMTP('localhost') as server:
                server.send_message(msg)
            print(f"Alert email sent to {self.alert_email}")
        except Exception as e:
            print(f"Failed to send alert email: {e}")

    def monitor(self, data_file, poll_interval=10):
        print("Starting real-time threat monitoring...")
        last_size = 0
        while True:
            try:
                data = pd.read_csv(data_file)
                if len(data) > last_size:
                    new_data = data.iloc[last_size:]
                    X_scaled = self.preprocess(new_data)
                    anomalies, mse = self.detect_anomalies(X_scaled)
                    for i, is_anomaly in enumerate(anomalies):
                        if is_anomaly:
                            message = f"Anomaly detected in new data row {last_size + i + 1} with MSE {mse[i]:.4f}"
                            self.send_alert(message)
                    last_size = len(data)
                time.sleep(poll_interval)
            except KeyboardInterrupt:
                print("Monitoring stopped by user.")
                break
            except Exception as e:
                print(f"Error during monitoring: {e}")
                time.sleep(poll_interval)

if __name__ == "__main__":
    monitor = RealTimeThreatMonitor(alert_email=None)  # Set alert_email to enable email alerts
    monitor.monitor('data/cybersecurity_logs.csv')
