#!/usr/bin/env python3
import argparse, csv, datetime as dt, io, os, re, sqlite3, sys, textwrap
from pathlib import Path
from typing import Iterable, Dict, List, Tuple
import requests
import tldextract

DB_PATH = Path("iocs.sqlite3")

# ---------- DB SETUP ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        indicator TEXT PRIMARY KEY,
        type      TEXT CHECK (type IN ('ip','domain','url','sha256','sha1','md5')),
        source    TEXT,
        first_seen TEXT,
        last_seen  TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS i_type ON iocs(type)")
    conn.execute("CREATE INDEX IF NOT EXISTS i_source ON iocs(source)")
    return conn

def iso_now():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

def upsert_iocs(conn, rows: Iterable[Tuple[str,str,str,str]]):
    # rows: (indicator, type, source, seen_time)
    for indicator, typ, source, seen in rows:
        conn.execute("""
        INSERT INTO iocs(indicator,type,source,first_seen,last_seen)
        VALUES (?,?,?,?,?)
        ON CONFLICT(indicator) DO UPDATE SET
          type=excluded.type,
          source=excluded.source,
          last_seen=excluded.last_seen
        """, (indicator, typ, source, seen, seen))
    conn.commit()

# ---------- FEEDS ----------
def fetch_urlhaus_online() -> List[Tuple[str,str,str,str]]:
    """
    URLHaus 'online' feed (CSV with '#' comments).
    We'll extract domains and urls.
    """
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    rows = []
    now = iso_now()
    content = "\n".join(line for line in r.text.splitlines() if not line.startswith("#"))
    reader = csv.reader(io.StringIO(content))
    # Columns: dateadded,url,url_status,threat,tags,urlhaus_link,reporter
    for cols in reader:
        if len(cols) < 2: 
            continue
        url_value = cols[1].strip()
        if not url_value or url_value.lower()=="url":
            continue
        # Save URL and registrable domain
        rows.append((url_value, "url", "urlhaus_online", now))
        ext = tldextract.extract(url_value)
        domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
        if domain:
            rows.append((domain.lower(), "domain", "urlhaus_online", now))
    return rows

def fetch_feodo_ips() -> List[Tuple[str,str,str,str]]:
    """
    Feodo Tracker IP blocklist (TXT). Lines with '#' are comments.
    """
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    rows = []
    now = iso_now()
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
            rows.append((line, "ip", "feodo_ipblocklist", now))
    return rows

def fetch_malwarebazaar_hashes(limit=200) -> List[Tuple[str,str,str,str]]:
    """
    MalwareBazaar recent samples via API (no key). POST query.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    try:
        r = requests.post(url, data={"query": "get_recent", "selector": "time"}, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []
    rows = []
    now = iso_now()
    for entry in data.get("data", [])[:limit]:
        h = entry.get("sha256")
        if h and re.match(r"^[A-Fa-f0-9]{64}$", h):
            rows.append((h.lower(), "sha256", "malwarebazaar_recent", now))
    return rows

def fetch_all():
    print("Fetching feeds…")
    total = 0
    conn = get_db()
    for name, fn in [
        ("URLHaus (online URLs & domains)", fetch_urlhaus_online),
        ("Feodo Tracker (IPs)", fetch_feodo_ips),
        ("MalwareBazaar (SHA256)", fetch_malwarebazaar_hashes),
    ]:
        try:
            items = fn()
            upsert_iocs(conn, items)
            print(f"  ✓ {name}: {len(items)} indicators")
            total += len(items)
        except Exception as e:
            print(f"  ! {name}: {e}")
    print(f"Done. Stored indicators: {count_iocs(conn)}")

def count_iocs(conn=None):
    close = False
    if conn is None:
        conn = get_db(); close=True
    cur = conn.execute("SELECT COUNT(*) FROM iocs")
    n = cur.fetchone()[0]
    if close: conn.close()
    return n

# ---------- CORRELATION ----------
IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOM_RE  = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

def correlate_file(path: Path, out_csv: Path=None):
    conn = get_db()
    hits: List[Dict] = []
    with path.open("r", errors="ignore") as f:
        for ln, line in enumerate(f, start=1):
            line_lower = line.strip().lower()

            def check(indicator, typ):
                cur = conn.execute("SELECT type, source, first_seen, last_seen FROM iocs WHERE indicator = ?", (indicator,))
                row = cur.fetchone()
                if row:
                    hits.append({
                        "line": ln,
                        "indicator": indicator,
                        "type": row[0],
                        "source": row[1],
                        "first_seen": row[2],
                        "last_seen": row[3],
                        "snippet": line.strip()[:300]
                    })

            for ip in set(IP_RE.findall(line_lower)):
                check(ip, "ip")
            for dom in set(DOM_RE.findall(line_lower)):
                # DOM_RE returns the last matched group sometimes; normalize with tldextract
                ext = tldextract.extract(dom)
                dom_norm = ".".join(p for p in [ext.domain, ext.suffix] if p)
                if dom_norm:
                    check(dom_norm, "domain")
            for h in set(SHA256_RE.findall(line_lower)):
                check(h.lower(), "sha256")


    # Print a compact report
    if hits:
        print(f"\n=== MATCHES in {path.name} ===")
        for h in hits:
            print(f"[line {h['line']}] {h['indicator']} ({h['type']})  ← {h['source']}")
            print(f"    {h['snippet']}")
        print(f"\nTotal matches: {len(hits)}")
    else:
        print("No matches found.")

    # Optional CSV export
    if out_csv:
        import pandas as pd
        pd.DataFrame(hits).to_csv(out_csv, index=False)
        print(f"Saved CSV: {out_csv}")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        prog="ti-aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""
        Threat Intelligence Feed Aggregator & Log Correlator

        Examples:
          python ti_aggregator.py fetch
          python ti_aggregator.py scan ./example.log --export matches.csv
          python ti_aggregator.py stats
        """)
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("fetch", help="Fetch all feeds and update the IOC database")
    pscan = sub.add_parser("scan", help="Scan a log file against the IOC database")
    pscan.add_argument("logfile", type=Path)
    pscan.add_argument("--export", type=Path, help="Export matches to CSV")
    sub.add_parser("stats", help="Show IOC counts")


    args = parser.parse_args()
    if args.cmd == "fetch":
        fetch_all()
    elif args.cmd == "scan":
        correlate_file(args.logfile, args.export)
    elif args.cmd == "stats":
        print(f"IOC count: {count_iocs()}")

if __name__ == "__main__":
    main()
