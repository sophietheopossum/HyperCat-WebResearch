import sys, time, datetime, urllib.parse; sys.path.insert(0,'.')
import backends
def probe(tag, hdrs, q="landlock abi"):
    url="https://html.duckduckgo.com/html/?q="+urllib.parse.quote(q, safe="")
    try:
        code, raw = backends._get(url, headers=hdrs, timeout=10)
    except Exception as e:
        print("%s %-26s ERR %s"%(datetime.datetime.now().strftime("%H:%M:%S"),tag,e), flush=True); return False
    ok = b"result__a" in raw
    print("%s %-26s code=%s len=%-6d %s" % (datetime.datetime.now().strftime("%H:%M:%S"),tag,code,len(raw),
          "OK" if ok else "BLOCKED"), flush=True)
    return ok
print("immediately after 3 urllib-UA requests:")
probe("browserUA now", {})
for i in range(10):
    time.sleep(60)
    if probe("browserUA t+%dm"%(i+1), {}):
        break
print("--- now test custom descriptive UAs (browser UA is working again) ---")
for ua in ["HyperCatWebSearch/0.1 (+https://example.invalid; local agent tool)",
           "Mozilla/5.0 (compatible; HyperCatWebSearch/0.1)",
           "curl/8.9.1"]:
    probe(ua[:26], {"User-Agent": ua}); time.sleep(8)
