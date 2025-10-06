# 🛡️ Threat Intelligence Feed Aggregator & Log Correlator (Python)

Fetches IOCs (IPs, domains, hashes) from open-source threat feeds and correlates them with log files for detection and reporting.

---

## 🚀 Features
- Fetches IOCs from:
  - URLHaus (malicious URLs/domains)
  - Feodo Tracker (IPs)
  - MalwareBazaar (hashes)
- Stores IOCs in SQLite with timestamps
- Scans any log file for matches
- Exports results to CSV

---

## 🧠 Skills Demonstrated
Python | Threat Intelligence | Regex | SQLite | Log Analysis | Cybersecurity Automation



# Threat Intelligence Feed Aggregator & Log Correlator (Python)

## Quickstart
```bash
# Step 0 — Create a workspace
mkdir threat-intel-aggregator
cd threat-intel-aggregator

# Step 1 — Python env & dependencies
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# Step 2 — Run it
python ti_aggregator.py fetch
python ti_aggregator.py stats
python ti_aggregator.py scan example.log --export matches.csv
```
