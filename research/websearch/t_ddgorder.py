import sys, time, datetime, urllib.parse, urllib.request, gzip; sys.path.insert(0,'.')
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
ACC_BROWSER="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
def raw_get(url, pairs, timeout=10):
    req=urllib.request.Request(url)
    for k,v in pairs: req.add_header(k,v)
    r=urllib.request.urlopen(req,timeout=timeout)
    b=r.read()
    if (r.headers.get("Content-Encoding","") or "").lower()=="gzip":
        try: b=gzip.decompress(b)
        except Exception: pass
    return r.status,b
def run(tag, pairs, qs):
    for q in qs:
        try:
            c,b=raw_get("https://html.duckduckgo.com/html/?q="+urllib.parse.quote(q,safe=""),pairs)
            print("%-30s code=%s len=%-6d hits=%d"%(tag,c,len(b),b.count(b"result__a")),flush=True)
        except Exception as e: print("%-30s ERR %s"%(tag,e),flush=True)
        time.sleep(4)
    time.sleep(8)
Q1=["landlock ruleset","seccomp notify","wayland dmabuf"]
Q2=["xwayland satellite","drm modifiers","fractional scale"]
Q3=["pipewire portal","vulkan hdr","edid parsing"]
Q4=["nvidia rtd3","btrfs raid","zram swap"]
run("UAfirst+browserAccept", [("User-Agent",UA),("Accept",ACC_BROWSER),("Accept-Language","en-GB,en;q=0.5"),("Accept-Encoding","gzip, deflate")], Q1)
run("UAlast+browserAccept",  [("Accept",ACC_BROWSER),("Accept-Language","en-GB,en;q=0.5"),("Accept-Encoding","gzip, deflate"),("User-Agent",UA)], Q2)
run("UAfirst+Accept*/*",     [("User-Agent",UA),("Accept","*/*"),("Accept-Language","en-US,en;q=0.9"),("Accept-Encoding","gzip, deflate")], Q3)
run("UAonly",                [("User-Agent",UA)], Q4)
