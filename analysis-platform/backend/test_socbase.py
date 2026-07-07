# -*- coding: utf-8 -*-
import requests
B = "http://localhost:8800"
spl = '`soc_base` | sort -_time | head 8 | table _time source_type signature severity src_ip dest_ip uri status'
r = requests.post(f"{B}/api/search", json={"spl": spl, "earliest": "-24h"}, timeout=180)
print("HTTP", r.status_code)
try:
    j = r.json()
except Exception as e:
    print("non-json:", r.text[:500]); raise
res = j.get("results")
if res is None:
    print("ERROR payload:", j)
else:
    print(f"매크로 해석 OK — {len(res)}건")
    for a in res[:8]:
        print(f"  [{str(a.get('source_type')):10}] {str(a.get('signature')):32} sev={a.get('severity')} {a.get('src_ip')}->{a.get('dest_ip')} {str(a.get('uri'))[:40]}")
