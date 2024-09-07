
# USB Forensics Tool - USB Device Activity Monitoring and Anomaly Detection




## Overview

 The USB Forensics Tool is a *Python*-based project designed to monitor USB device activity on **Windows systems**, detect malicious USB devices by scanning for suspicious file types, and use **machine learning** to identify anomalous behavior in USB usage patterns. The tool also features real-time USB monitoring and can send **email alerts** when malicious or suspicious activity is **detected**.




##  Requirements
- **Python 3.x**
- **Windows OS** (this tool is designed to work on Windows)
- *Python Libraries*:
   - ```wmi```
    - ```winreg```
    - ```smtplib```
    - ```datetime```
   - ```matplotlib```
  -  ```seaborn```
   -  ```numpy```
   -  ```sklearn``` (Isolation Forest)
## Features

- **USB Device History Extraction**: Retrieves detailed information about USB devices connected to the system from the Windows Registry.
- **Real-Time USB Monitoring**: Detects USB devices in real-time and performs security checks upon connection.
- **Malware Detection**: Scans for suspicious file extensions (e.g., ```.exe```,```.bat```, ```.vbs```, ```.js```) and flags potentially harmful USB devices.
- **Anomaly Detection**: Uses an Isolation Forest model to identify unusual USB activity.
- **Email Alerts**: Sends an alert via email when a potentially malicious USB device is detected.
- **Data Visualization**: Visualizes USB connection times to track activity trends.

## How It Works

The tool monitors the system's **USB ports and analyzes connected USB devices**. It scans for suspicious files and **flags** them if detected. The tool also provides anomaly detection using **machine learning (Isolation Forest)** and sends **email alerts** when malicious activity is identified.

##  Main Components:
**USB History Scanning**:

- Retrieves USB device details like **device ID**, **manufacturer**, and **installation date** from the **registry**.
- Scans for suspicious files (e.g.,**```.exe```, ```.bat```, ```.vbs```**).
**Real-Time Monitoring**:

- Watches for new USB devices being connected and triggers security checks. 
**Anomaly Detection**:

- Collects USB activity data and uses machine learning to flag unusual behavior in device usage.
**Email Alerts**:

- Sends an email alert when malicious devices or anomalies are detected.
**Visualization**:

- Visualizes USB activity data (e.g., **connection times**) using 
**```matplotlib```** and **nbbb``` seaborn```**.







## Setup
 ### 1. Configure Email Alerts
 You need to configure the email settings in the script to send alerts when suspicious activity is detected:
 ```
 SMTP_SERVER = "smtp.yourprovider.com"
SMTP_PORT = 587
EMAIL_USER = "your-email@example.com"
EMAIL_PASS = "your-password"
ALERT_EMAIL = "admin@example.com"
 ```

  ### 2. Running the Tool
 You can run the tool by executing the script in a Python environment (VS Code or any other Python IDE). Make sure the tool runs on a Windows machine, as it uses Windows-specific APIs and registry paths.

 **To run the script:**

 ```
 python usb_forensics_tool.py

 ```
 **Real-Time Monitoring:**
 You can enable real-time monitoring by uncommenting the following line in the main section of the code:
  ```
monitor_usb_real_time()

 ```
 This will continuously monitor USB ports for new devices.

 ## Output Scenarios
  ### 1. No USB Device Connected:
  If no USB devices are detected, the tool will output:

```No USB devices were found in the system history.```
 ### 2.Safe USB Device:
  If the connected USB device is safe:

```USB device is safe to use.```


 ### 3.Malicious USB Device:
 If a USB device contains suspicious files:



``` 
ALERT: Suspicious Files Found 
USB device may be unsafe. Alerts have been sent.
```

### 4.Anomaly Detection:
 If an anomaly in USB activity is detected:



```  ALERT: Anomaly detected in USB connection pattern.```




## Example OUTPUT
```
# USB Forensics Tool - Execution Log

Device: SanDisk Cruzer
  ID: USB\VID_0781&PID_5567
  Manufacturer: SanDisk
  First Install Date: 05-Sep-2024 14:32:45
  ** ALERT: Suspicious Files Found **
--------------------------------------
USB device may be unsafe. Alerts have been sent.
```

## Screenshot:

![App Screenshot](https://github.com/user-attachments/assets/71016a28-3e65-4d96-b910-9c835f25842a)


## Future Improvements
- **Enhanced ML Models**: Train and integrate more advanced models for anomaly detection.
- **Cross-Platform Support**: Extend support for macOS and Linux.
- **File Quarantine**: Add features to quarantine suspicious files automatically.




## Contribution
 **Contributions, suggestions, and improvements are welcome! Feel free to submit a pull request or open an issue to improve the tool.**

## 🚀 About Me
Hi, I’m **Aakash**, a **sophomore** pursuing **Computer Science Engineering** at **DTU**. With a passion for technology and innovation, I’m diving deep into the world of **computer science**, exploring everything from **machine learning** to **cybersecurity**.


## 🔗 Links

[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/aakash-chaurasia-630822280/)


