import sys, gzip, zlib, io, time, json
import urllib.request, urllib.parse, urllib.error

UA_REAL = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

def fetch(url, data=None, headers=None, timeout=15):
    h = {"Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate"}
    if headers: h.update(headers)
    if data is not None and isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=data, headers=h)
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        raw = r.read()
        code, hdrs, final = r.status, r.headers, r.url
    except urllib.error.HTTPError as e:
        raw = e.read(); code, hdrs, final = e.code, e.headers, url
    except Exception as e:
        return {"err": "%s: %s" % (type(e).__name__, e), "dt": time.time()-t0}
    enc = (hdrs.get("Content-Encoding","") or "").lower()
    if enc == "gzip":
        try: raw = gzip.decompress(raw)
        except Exception: pass
    elif enc == "deflate":
        try: raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception: pass
    return {"code": code, "final": final, "ct": hdrs.get("Content-Type",""),
            "len": len(raw), "dt": round(time.time()-t0,2), "body": raw,
            "hdrs": {k:v for k,v in dict(hdrs).items() if k.lower() in
                     ("server","x-ratelimit-limit","x-ratelimit-remaining","retry-after","set-cookie","cf-ray","x-cache")}}

def show(tag, r, n=400):
    if "err" in r:
        print("== %s -> ERROR %s (%.1fs)" % (tag, r["err"], r["dt"])); return
    print("== %s -> %s %s len=%d %.2fs %s" % (tag, r["code"], r["ct"], r["len"], r["dt"], r["hdrs"]))
    b = r["body"][:n]
    try: print(b.decode("utf-8","replace").replace("\n"," ")[:n])
    except Exception: print(repr(b))
    print()
