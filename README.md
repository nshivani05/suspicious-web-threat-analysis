# Suspicious Web Threat Analysis using AWS CloudWatch Logs

This project analyzes web server traffic logs collected from AWS CloudWatch to detect suspicious activity, identify threat sources, and visualize patterns of malicious behavior. Using Python, Pandas, and data visualization libraries, it flags anomalies and supports real-time monitoring for cybersecurity teams.

---
## Live Demo:
https://suspicious-web-threat-analyzer-txt5bs2rt98gue43cwenge.streamlit.app/

## 🎯 Project Objectives

- Analyze suspicious web interactions from production server logs  
- Identify top attacker IPs and potential threat origins  
- Detect traffic anomalies that may signal serious security risks  
- Support cloud-based incident response and monitoring  

---

## 🧰 Tools & Technologies Used

- **AWS CloudWatch** – Log data source  
- **Python** – Analysis and scripting  
- **Pandas** – Data transformation  
- **Matplotlib & Seaborn** – Visualization  
- **Google Colab** – Development environment  

---

## 📊 Key Insights

- Peak attack activity between 11 AM and 3 PM on weekdays  
- Multiple threat detections triggered by small sets of IPs  
- Common detection rules: port scans, injection attempts, exploit probes  
- Protocol analysis reveals use of suspicious ports  
- Anomalies flagged using `bytes_out` threshold (Top 5%)  

---
<img width="843" height="470" alt="image" src="https://github.com/user-attachments/assets/df898c6a-f91b-40c0-8b41-61dc2d3c2482" />
<img width="942" height="470" alt="image" src="https://github.com/user-attachments/assets/5d69e7ee-d02d-4662-96b6-9292e3091ff0" />

