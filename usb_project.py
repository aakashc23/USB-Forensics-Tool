import os
import sys
import winreg as reg
import wmi
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.ensemble import IsolationForest

# Email settings
SMTP_SERVER = "smtp.yourprovider.com"
SMTP_PORT = 587
EMAIL_USER = "your-email@example.com"
EMAIL_PASS = "your-password"
ALERT_EMAIL = "admin@example.com"

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".vbs", ".js", ".msi", ".cmd"]

# Data collection for USB activity
usb_usage_data = []

# Pre-trained Isolation Forest model (replace with a trained model)
isolation_forest = IsolationForest(n_estimators=100, contamination=0.01)

def send_email_alert(device_id, alert_message):
    """Send an email alert when suspicious USB activity is detected."""
    try:
        msg = MIMEText(f"Alert for USB Device ID: {device_id}\n\n{alert_message}")
        msg['Subject'] = 'USB Device Alert'
        msg['From'] = EMAIL_USER
        msg['To'] = ALERT_EMAIL

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, ALERT_EMAIL, msg.as_string())
        print(f"Alert sent for device: {device_id}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

def get_usb_history():
    """Retrieve the history of USB devices connected to the system."""
    path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    safe_device = True  # Assume the device is safe unless suspicious activity is detected

    try:
        reg_key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
        i = 0
        while True:
            try:
                subkey_name = reg.EnumKey(reg_key, i)
                subkey_path = path + "\\" + subkey_name
                subkey = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, subkey_path)

                # Extract USB device details
                friendly_name = reg.QueryValueEx(subkey, "FriendlyName")[0]
                device_id = reg.QueryValueEx(subkey, "DeviceID")[0]
                manufacturer = reg.QueryValueEx(subkey, "Manufacturer")[0]
                first_install_date = reg.QueryValueEx(subkey, "FirstInstallDate")[0]
                first_install_date = datetime.strptime(first_install_date, '%Y-%m-%d %H:%M:%S').strftime('%d-%b-%Y %H:%M:%S')

                print(f"\nDevice: {friendly_name}\n  ID: {device_id}\n  Manufacturer: {manufacturer}\n  First Install Date: {first_install_date}")

                # Track USB usage
                log_usb_usage(device_id)

                # Check for potential malware based on suspicious files
                if check_for_suspicious_files(subkey_path):
                    print("  ** ALERT: Suspicious Files Found **")
                    send_email_alert(device_id, "Suspicious files detected.")
                    safe_device = False

                print("-" * 40)
                i += 1
            except OSError:
                break
    except FileNotFoundError:
        print("Registry path not found.")
    finally:
        reg.CloseKey(reg_key)

    # Safety message based on scan result
    print("USB device is safe." if safe_device else "USB device may be unsafe. Alerts have been sent.")

def check_for_suspicious_files(subkey_path):
    """Check if the subkey contains files with suspicious extensions."""
    return any(subkey_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

def log_usb_usage(device_id):
    """Log USB usage for activity tracking."""
    usb_usage_data.append({
        "device_id": device_id,
        "timestamp": datetime.now(),
        "action": "Connected"
    })

def visualize_usb_activity():
    """Visualize USB connection times using a histogram."""
    if not usb_usage_data:
        print("No USB activity to display.")
        return
    
    timestamps = [entry["timestamp"] for entry in usb_usage_data]
    sns.histplot(timestamps, kde=True)
    plt.title("USB Device Connection Times")
    plt.xlabel("Timestamp")
    plt.ylabel("Frequency")
    plt.show()

def monitor_usb_real_time():
    """Monitor USB devices in real-time using WMI."""
    c = wmi.WMI()
    watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_USBControllerDevice")
    
    print("Monitoring real-time USB activity...")
    while True:
        try:
            usb_event = watcher()
            device_id = usb_event.Dependent.DeviceID
            print(f"Real-time USB Device Event Detected!\n  Device ID: {device_id}")
            log_usb_usage(device_id)
            # Additional checks can be added here for real-time alerting.
        except KeyboardInterrupt:
            print("Monitoring stopped.")
            break

def detect_anomalies():
    """Run an Isolation Forest algorithm to detect anomalies in USB activity."""
    if len(usb_usage_data) < 2:
        print("Not enough USB activity data to detect anomalies.")
        return

    # Example feature matrix (replace with actual feature extraction)
    X = np.random.rand(len(usb_usage_data), 2)
    isolation_forest.fit(X)
    predictions = isolation_forest.predict(X)
    
    anomalies = [usb_usage_data[i] for i, pred in enumerate(predictions) if pred == -1]
    if anomalies:
        print(f"Detected {len(anomalies)} anomalies in USB activity.")
    else:
        print("No anomalies detected.")

if __name__ == "__main__":
    if os.name != "nt":
        print("This script is intended to run on Windows systems only.")
        sys.exit(1)

    print("USB Device History with Enhanced Security Monitoring:\n")
    
    # Static Analysis of USB Device History
    get_usb_history()
    visualize_usb_activity()

    # Example Anomaly Detection
    detect_anomalies()

    # Uncomment for real-time USB monitoring (blocking operation)
    # monitor_usb_real_time()
