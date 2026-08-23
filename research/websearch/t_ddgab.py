import sys, time, datetime, urllib.parse; sys.path.insert(0,'.')
import probe as P, backends as B
QS=["ext-image-copy-capture","xdg-output logical","smithay renderer","fifo commit timing"]
def line(tag,code,raw): print("%s %-18s code=%s len=%-6d hits=%d"%(datetime.datetime.now().strftime("%H:%M:%S"),tag,code,len(raw),raw.count(b"result__a")),flush=True)
print("--- A: probe.fetch (Accept:*/*, AL en-US;q=0.9), 4s ---")
for q in QS:
    r=P.fetch("https://html.duckduckgo.com/html/?q="+urllib.parse.quote(q),headers={"User-Agent":P.UA_REAL})
    line("probe.fetch",r.get("code"),r.get("body",b"")); time.sleep(4)
time.sleep(6)
print("--- B: backends._get, 4s ---")
for q in QS:
    c,raw=B._get("https://html.duckduckgo.com/html/?q="+urllib.parse.quote(q,safe=""))
    line("backends._get",c,raw); time.sleep(4)
