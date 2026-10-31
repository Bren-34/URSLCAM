"""
Run once:  python seed_neo4j.py
- Loads the red-flag checklist into Neo4j
- Loads known phishing domains from the free OpenPhish feed (stored as text only, never opened)
- Optional: if PhiUSIIL_Phishing_URL_Dataset.csv is in this folder, prints how often page
  features appear on phishing vs legit pages (handy numbers for your demo)
"""
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

from common import DEFAULT_RED_FLAGS, host_of, registered_domain
from graph import Graph

g = Graph()
if not g.online:
    raise SystemExit("Could not connect to Neo4j. Check NEO4J_URI / NEO4J_USERNAME / NEO4J_PASSWORD in .env")

print("Creating constraints...")
for q in [
    "CREATE CONSTRAINT redflag_key IF NOT EXISTS FOR (f:RedFlag) REQUIRE f.key IS UNIQUE",
    "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
    "CREATE CONSTRAINT brand_name IF NOT EXISTS FOR (b:Brand) REQUIRE b.name IS UNIQUE",
    "CREATE CONSTRAINT datatype_name IF NOT EXISTS FOR (x:DataType) REQUIRE x.name IS UNIQUE",
]:
    g._run(q)

print("Loading red flags...")
g._run("UNWIND $rows AS r MERGE (f:RedFlag {key:r.key}) SET f.description = r.d, f.weight = r.w",
       rows=[{"key": k, "d": d, "w": w} for k, (d, w) in DEFAULT_RED_FLAGS.items()])

print("Downloading OpenPhish feed...")
try:
    feed = requests.get("https://openphish.com/feed.txt", timeout=30).text.split()
    doms = sorted({registered_domain(host_of(u)) for u in feed if u.startswith("http")} - {""})
    # skip big shared hosting platforms so we don't mark e.g. all of github.io as bad
    shared = {"github.io", "vercel.app", "netlify.app", "web.app", "firebaseapp.com", "pages.dev",
              "weebly.com", "wixsite.com", "blogspot.com", "google.com", "glitch.me", "000webhostapp.com",
              "ipfs.io", "workers.dev", "herokuapp.com", "godaddysites.com", "square.site", "webflow.io"}
    doms = [d for d in doms if d not in shared]
    g._run("UNWIND $names AS n MERGE (d:Domain {name:n}) SET d.known_bad = true, d.source = 'openphish'",
           names=doms)
    print(f"  loaded {len(doms)} known-bad domains")
except Exception as e:
    print(f"  OpenPhish download failed ({e}) - skipping")

csv = Path("PhiUSIIL_Phishing_URL_Dataset.csv")
if csv.exists():
    import pandas as pd
    df = pd.read_csv(csv)
    cols = [c for c in ["HasPasswordField", "HasExternalFormSubmit", "HasHiddenFields", "HasSubmitButton",
                        "Bank", "Pay", "Crypto", "HasCopyrightInfo", "HasSocialNet", "HasFavicon",
                        "HasTitle", "IsHTTPS"] if c in df.columns]
    print(f"\nPhiUSIIL ({len(df):,} URLs) - % of pages with each feature:")
    t = (df.groupby("label")[cols].mean().T * 100).round(1).rename(columns={0: "phishing %", 1: "legit %"})
    print(t.to_string())
    for c in ["NoOfExternalRef", "NoOfSelfRef", "NoOfiFrame"]:
        if c in df.columns:
            m = df.groupby("label")[c].mean().round(1)
            print(f"  avg {c}: phishing {m.get(0)}, legit {m.get(1)}")
else:
    print("\n(Optional) put PhiUSIIL_Phishing_URL_Dataset.csv here to print dataset stats.")

print("\nDone ✅  Neo4j is seeded.")
