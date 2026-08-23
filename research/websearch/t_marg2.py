from probe import *
QS = ["prompt injection defense llm","rust ra_ap_syntax","how to make sourdough starter","openssl 3.6 release notes"]
for q in QS:
    for attempt in (1,2):
        url = "https://api.marginalia.nu/public/search/" + urllib.parse.quote(q)
        r = fetch(url, headers={"User-Agent":"HyperCatWebSearch/0.1"}, timeout=40)
        if "err" in r: print("%-30s try%d ERR %s (%.1fs)" % (q[:30],attempt,r["err"],r["dt"])); continue
        d = json.loads(r["body"])
        print("%-30s try%d code=%s n=%d %.2fs" % (q[:30],attempt,r["code"],len(d.get("results",[])),r["dt"]))
        break
    time.sleep(1)
