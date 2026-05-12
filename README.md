# 🚀 AI Threat Detection Dashboard

An AI-inspired SOC threat detection dashboard that analyzes security events, assigns dynamic risk scores, and generates automated incident response recommendations.

---

# 📌 Overview

This project simulates how modern Security Operations Center (SOC) teams prioritize threats using:

- Risk-based alerting
- Event correlation
- Threat scoring
- Automated incident response recommendations

The dashboard processes simulated security logs and identifies potentially compromised users based on suspicious behavior patterns.

---

# ⚠️ Problem

SOC analysts receive thousands of security alerts daily.

Manual investigation is:

- Time-consuming
- Difficult to prioritize
- Prone to alert fatigue
- Hard to scale efficiently

Organizations need automated ways to:

- Detect suspicious activity
- Prioritize threats
- Recommend response actions

---

# 💡 Solution

This Python-based threat detection dashboard:

- Parses security event logs
- Assigns weighted risk scores to suspicious activity
- Correlates multiple attack behaviors
- Calculates user risk levels
- Generates automated response recommendations
- Exports investigation results into a structured report

---

# 🧠 Risk Scoring Logic

| Event Type | Risk Points |
|---|---|
| EMAIL_RECEIVED | 5 |
| LINK_CLICKED | 25 |
| LOGIN_FAILED | 10 |
| LOGIN_SUCCESS from suspicious location | 45 |
| PASSWORD_CHANGED | 30 |
| MAILBOX_FORWARDING_ENABLED | 50 |

---

# 🚨 Risk Levels

| Risk Score | Risk Level |
|---|---|
| 150+ | 🔴 HIGH |
| 60–149 | 🟠 MEDIUM |
| Below 60 | 🟢 LOW |

---

# 🧪 Example Output

```text
=== AI Threat Detection Risk Report ===

User: dipan
Risk Score: 175
Risk Level: HIGH

Recommendation:
Disable account, reset password, remove forwarding rules, and investigate immediately.
```

---

# 📸 Execution Output

<img width="1264" height="1250" alt="image" src="https://github.com/user-attachments/assets/7962bbee-4e58-4b77-8c58-12e970278d40" />

---

# 🧾 Sample Security Events

```text
2026-05-10 09:01:22 USER=dipan EVENT=EMAIL_RECEIVED SUBJECT="Urgent Password Reset"

2026-05-10 09:02:10 USER=dipan EVENT=LINK_CLICKED URL="http://fake-microsoft-login.com"

2026-05-10 09:04:15 USER=dipan EVENT=LOGIN_SUCCESS IP=185.22.44.10 LOCATION=Russia

2026-05-10 09:06:55 USER=dipan EVENT=MAILBOX_FORWARDING_ENABLED
```

---

# 📄 Generated Report

The program automatically creates:

```text
risk_report.txt
```

This simulates how enterprise SOC tools generate investigation and incident response reports.

---

# 🛠 Technologies Used

- Python
- Regular Expressions (Regex)
- File Handling
- Risk Scoring Logic
- Threat Correlation
- SOC Detection Workflow

---

# 🧠 Skills Demonstrated

- SOC investigation workflow
- Detection engineering concepts
- Threat prioritization
- Event correlation
- Risk-based alerting
- Incident response logic
- Python automation
- Security reporting

---

# 🌍 Real-World SOC Relevance

This project simulates how modern SOC teams prioritize alerts using risk-based detection and automated incident response logic.

The workflow reflects real-world processes used in:

- SIEM platforms
- Threat detection systems
- SOC monitoring environments
- Detection engineering teams

This project demonstrates the transition from:

```text
Raw Logs → Detection → Correlation → Risk Scoring → Response Recommendation
```

---

# ⚙️ How to Run

```bash
git clone https://github.com/Dipan-Khatri/AI-Threat-Detection-Dashboard.git

cd AI-Threat-Detection-Dashboard

python main.py
```

---

# 📂 Project Files

```text
main.py
security_events.txt
risk_report.txt
README.md
```

---

# 🔮 Future Improvements

- Real-time event monitoring
- Machine learning risk scoring
- Web dashboard visualization
- Splunk integration
- CSV/JSON export support
- MITRE ATT&CK mapping integration
- Automated alert generation

---

# 👨‍💻 Author

## Dipan Khatri

Cybersecurity Enthusiast | Aspiring SOC Analyst

GitHub:
https://github.com/Dipan-Khatri

LinkedIn:
https://www.linkedin.com/in/dipan-khatri/
