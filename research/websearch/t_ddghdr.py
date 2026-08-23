import sys, time, datetime, urllib.parse; sys.path.insert(0,'.')
import backends
def try_hdr(tag, hdrs, q):
    url="https://html.duckduckgo.com/html/?q="+urllib.parse.quote(q, safe="")
    code, raw = backends._get(url, headers=hdrs, timeout=10)
    body=raw.decode("utf-8","replace")
    ok = "result__a" in body
    print("%s %-38s code=%s len=%-6d results=%s" % (datetime.datetime.now().strftime("%H:%M:%S"),
          tag, code, len(raw), body.count('result__a') if ok else "BLOCKED"), flush=True)
QS=["ext image copy capture protocol","openssl 3.6 changes","fish shell abbr","landlock abi 5","wl_fixed rounding"]
print("--- A: browser Accept (backends default), 2s gap ---")
for q in QS: try_hdr("browser-Accept", {}, q); time.sleep(2)
time.sleep(8)
print("--- B: Accept: */* (probe.py style), 2s gap ---")
for q in QS: try_hdr("Accept:*/*", {"Accept":"*/*"}, q); time.sleep(2)
time.sleep(8)
print("--- C: default urllib UA, browser Accept ---")
for q in QS[:3]: try_hdr("urllib-UA", {"User-Agent":"Python-urllib/3.14"}, q); time.sleep(2)
