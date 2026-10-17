"""Builds index.html from site_template.html and a scan results file.

    python build_site.py                       # uses scan_results.json
    python build_site.py --data other.json
"""
import argparse
import json
from pathlib import Path

here = Path(__file__).parent
ap = argparse.ArgumentParser()
ap.add_argument("--data", default="scan_results.json")
ap.add_argument("--out", default="index.html")
args = ap.parse_args()

data = json.loads((here / args.data).read_text())
html = (here / "site_template.html").read_text()
# Escape "</" so record text can never close the <script> tag early
payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
(here / args.out).write_text(html.replace("__DATA__", payload))
ok = [d for d in data["domains"] if not d.get("error")]
print(f"{args.out}: {len(ok)} domains, scanned {data['scanned_at']}" + ("  [SAMPLE DATA]" if data.get("sample_data") else ""))
