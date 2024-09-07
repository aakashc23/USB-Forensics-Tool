import os
import sys
import winreg as reg
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import pairwise_distances_argmin_min

# Example of data collection for ML model
usb_usage_data = []
APPROVED_DEVICES = ["1234567890", "0987654321"]
SENSITIVE_FILES = ["important_file.txt"]

# Email settings
SMTP_SERVER = "smtp.yourprovider.com"
SMTP_PORT = 587
EMAIL_USER = "your-email@example.com"
EMAIL_PASS = "your-password"
ALERT_EMAIL = "admin@example.com"

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".vbs", ".js", ".msi", ".cmd"]

def send_email_alert(device_id, alert_message):
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(f"Alert for USB Device ID: {device_id}\n\n{alert_message}")
    msg['Subject'] = 'USB Device Alert'
    msg['From'] = EMAIL_USER
    msg['To'] = ALERT_EMAIL

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, ALERT_EMAIL, msg.as_string())

def get_usb_history():
    path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    
    try:
        reg_key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
    except FileNotFoundError:
        print("Registry path not found.")
        sys.exit(1)
    
    try:
        i = 0
        while True:
            subkey_name = reg.EnumKey(reg_key, i)
            subkey_path = path + "\\" + subkey_name
            subkey = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, subkey_path)
            
            # Extract USB device details
            friendly_name = reg.QueryValueEx(subkey, "FriendlyName")[0]
            device_id = reg.QueryValueEx(subkey, "DeviceID")[0]
            manufacturer = reg.QueryValueEx(subkey, "Manufacturer")[0]
            first_install_date = reg.QueryValueEx(subkey, "FirstInstallDate")[0]
            first_install_date = datetime.strptime(first_install_date, '%Y-%m-%d %H:%M:%S').strftime('%d-%b-%Y %H:%M:%S')
            
            print(f"Device: {friendly_name}")
            print(f"  ID: {device_id}")
            print(f"  Manufacturer: {manufacturer}")
            print(f"  First Install Date: {first_install_date}")
            
            # Track USB usage for anomaly detection
            usb_usage_data.append({
                "device_id": device_id,
                "timestamp": datetime.now(),
                "action": "Connected"
            })
            
            # Check for potential malware
            if check_for_suspicious_files(subkey_path):
                print("  ** ALERT: Potentially Malicious Files Found **")
                send_email_alert(device_id, "Suspicious files detected.")

            print("-" * 40)
            i += 1
    except OSError:
        pass
    finally:
        reg.CloseKey(reg_key)

def check_for_suspicious_files(subkey_path):
    for extension in SUSPICIOUS_EXTENSIONS:
        if subkey_path.endswith(extension):
            return True
    return False

def kmeans_anomaly_detection():
    # Prepare data for K-Means
    features = np.array([[entry["timestamp"].hour] for entry in usb_usage_data])
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    # Fit K-Means model
    kmeans = KMeans(n_clusters=3, random_state=0).fit(features_scaled)
    distances = kmeans.transform(features_scaled)
    
    # Detect anomalies
    anomaly_threshold = np.percentile(distances.min(axis=1), 95)
    anomalies = np.where(distances.min(axis=1) > anomaly_threshold)[0]
    
    for idx in anomalies:
        print(f"Anomaly detected: {usb_usage_data[idx]['device_id']} at {usb_usage_data[idx]['timestamp']}")

def visualize_usb_activity():
    # Example visualization
    timestamps = [entry["timestamp"] for entry in usb_usage_data]
    sns.histplot(timestamps, kde=True)
    plt.title("USB Device Connection Times")
    plt.xlabel("Timestamp")
    plt.ylabel("Frequency")
    plt.show()

if __name__ == "__main__":
    if os.name != "nt":
        print("This script is intended to run on Windows systems only.")
        sys.exit(1)
    
    print("USB Device History with Advanced Security Features:\n")
    get_usb_history()
    kmeans_anomaly_detection()
    visualize_usb_activity()
