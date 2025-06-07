import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras import layers, models, callbacks
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

# Load and preprocess data
def load_data(file_path):
    data = pd.read_csv(file_path)
    # Assuming the last column is the label (0 for normal, 1 for anomaly)
    X = data.iloc[:, :-1].values
    y = data.iloc[:, -1].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return train_test_split(X_scaled, y, test_size=0.2, random_state=42), scaler

# Build an enhanced autoencoder for anomaly detection
def build_autoencoder(input_dim):
    input_layer = layers.Input(shape=(input_dim,))
    encoded = layers.Dense(64, activation='relu')(input_layer)
    encoded = layers.Dropout(0.2)(encoded)
    encoded = layers.Dense(32, activation='relu')(encoded)
    encoded = layers.Dropout(0.2)(encoded)
    encoded = layers.Dense(16, activation='relu')(encoded)
    decoded = layers.Dense(32, activation='relu')(encoded)
    decoded = layers.Dropout(0.2)(decoded)
    decoded = layers.Dense(64, activation='relu')(decoded)
    decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
    autoencoder = models.Model(inputs=input_layer, outputs=decoded)
    autoencoder.compile(optimizer='adam', loss='mse')
    return autoencoder

def train(file_path):
    (X_train, X_test, y_train, y_test), scaler = load_data(file_path)
    input_dim = X_train.shape[1]
    autoencoder = build_autoencoder(input_dim)
    early_stop = callbacks.EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
    history = autoencoder.fit(X_train, X_train,
                              epochs=100,
                              batch_size=32,
                              validation_data=(X_test, X_test),
                              callbacks=[early_stop])
    autoencoder.save('models/anomaly_autoencoder.h5')
    # Save scaler for inference
    import joblib
    joblib.dump(scaler, 'models/scaler.save')

    # Evaluate model
    X_test_pred = autoencoder.predict(X_test)
    mse = np.mean(np.power(X_test - X_test_pred, 2), axis=1)
    threshold = np.percentile(mse, 95)  # 95th percentile as threshold
    y_pred = (mse > threshold).astype(int)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    print(f"Precision: {precision:.4f}, Recall: {recall:.4f}, F1-score: {f1:.4f}")

if __name__ == "__main__":
    import os
    os.makedirs('models', exist_ok=True)
    # Replace 'data/cybersecurity_logs.csv' with your actual data file path
    train('data/cybersecurity_logs.csv')
