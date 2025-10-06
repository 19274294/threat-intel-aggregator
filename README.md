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
