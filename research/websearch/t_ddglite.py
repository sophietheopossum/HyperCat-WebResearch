from probe import *
def probe(tag, url, data=None, hdr=None, marker=b"result__a"):
    r = fetch(url, data=data, headers=hdr)
    n = r.get("body", b"").count(marker)
    print("%-32s code=%s len=%s marker=%d %.2fs" % (tag, r.get("code", r.get("err")), r.get("len"), n, r.get("dt",0)))
    return r
Q="landlock seccomp sandbox"; qq=urllib.parse.quote(Q)
# lite first (clean, after long DDG cooldown)
r = probe("lite GET realUA", "https://lite.duckduckgo.com/lite/?q="+qq, None, {"User-Agent": UA_REAL}, b"result-link")
open("out_lite1.bin","wb").write(r.get("body",b""))
time.sleep(6)
r = probe("lite POST realUA", "https://lite.duckduckgo.com/lite/", {"q":Q}, {"User-Agent": UA_REAL}, b"result-link")
open("out_lite2.bin","wb").write(r.get("body",b""))
time.sleep(6)
r = probe("html GET realUA", "https://html.duckduckgo.com/html/?q="+qq, None, {"User-Agent": UA_REAL})
open("out_html1.bin","wb").write(r.get("body",b""))
