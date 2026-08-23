import sys, time, datetime, urllib.parse; sys.path.insert(0,'.')
import backends
def probe(tag, url, data=None, hdrs=None, marker=b"result__a"):
    try:
        code, raw = backends._get(url, data=data, headers=hdrs, timeout=10)
    except Exception as e:
        print("%-34s ERR %s"%(tag,e), flush=True); return
    print("%s %-34s code=%s len=%-6d hits=%d" % (datetime.datetime.now().strftime("%H:%M:%S"),
          tag, code, len(raw), raw.count(marker)), flush=True)
q="landlock seccomp"; qq=urllib.parse.quote(q, safe="")
probe("html GET  browserUA", "https://html.duckduckgo.com/html/?q="+qq); time.sleep(6)
probe("html POST browserUA", "https://html.duckduckgo.com/html/", {"q":q}); time.sleep(6)
probe("lite GET  browserUA", "https://lite.duckduckgo.com/lite/?q="+qq, None, None, b"result-link"); time.sleep(6)
probe("lite POST browserUA", "https://lite.duckduckgo.com/lite/", {"q":q}, None, b"result-link"); time.sleep(6)
probe("lite GET  browserUA (a-tag)", "https://lite.duckduckgo.com/lite/?q="+qq, None, None, b"<a "); time.sleep(6)
# repeat the exact earlier failing pattern: 6 queries @4s, browser UA, html GET
print("--- 6 queries @4s, html GET, browser UA ---")
for q2 in ["python urllib user agent","wayland compositor smithay","prompt injection defense",
           "rust ra_ap_syntax","quickshell qml","landlock network"]:
    probe(q2[:34], "https://html.duckduckgo.com/html/?q="+urllib.parse.quote(q2, safe="")); time.sleep(4)
