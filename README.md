# Suspicious Web Threat Analysis using AWS CloudWatch Logs

This project analyzes web server traffic logs collected from AWS CloudWatch to detect suspicious activity, identify threat sources, and visualize patterns of malicious behavior. Using Python, Pandas, and data visualization libraries, it flags anomalies and supports real-time monitoring for cybersecurity teams.

## Live Demo:
https://suspicious-web-threat-analyzer-txt5bs2rt98gue43cwenge.streamlit.app/

## 🎯 Project Objectives

- Analyze suspicious web interactions from production server logs  
- Identify top attacker IPs and potential threat origins  
- Detect traffic anomalies that may signal serious security risks  
- Support cloud-based incident response and monitoring  

---

## 🧰 Tools & Technologies Used

Python 3.x
Streamlit – for creating the web app interface
Pandas – for data manipulation and preprocessing
Seaborn & Matplotlib – for detailed data visualization
Altair – for interactive country-level charts
PyCountry – for converting country codes to full names
AWS CloudWatch Logs – data source representing web traffic and security alerts

---

## 📊 Key Insights

- Peak attack activity between 11 AM and 3 PM on weekdays  
- Multiple threat detections triggered by small sets of IPs  
- Common detection rules: port scans, injection attempts, exploit probes  
- Protocol analysis reveals use of suspicious ports  
- Anomalies flagged using `bytes_out` threshold (Top 5%)

## How to Run locally
```
# clone the repo
git clone https://github.com/nshivani05/suspicious-web-threat-analysis.git
cd suspicious-web-threat-analysis
# (Optional) Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate  # for Windows
# Install required libraries
pip install -r requirements.txt
# Run the Streamlit app
streamlit run app2.py
```

---
<img width="843" height="470" alt="image" src="https://github.com/user-attachments/assets/df898c6a-f91b-40c0-8b41-61dc2d3c2482" />
<img width="942" height="470" alt="image" src="https://github.com/user-attachments/assets/5d69e7ee-d02d-4662-96b6-9292e3091ff0" />

