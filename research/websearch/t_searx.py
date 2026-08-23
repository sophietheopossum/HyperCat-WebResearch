import re
from probe import *
Q="landlock seccomp sandbox"; qq=urllib.parse.quote(Q)
inst = ["https://search.inetol.net","https://priv.au","https://opnxng.com",
        "https://searx.tiekoetter.com","https://paulgo.io","https://searxng.site",
        "https://search.bus-hit.me","https://search.rhscz.eu","https://baresearch.org",
        "https://searx.perennialte.ch"]
for base in inst:
    for mode,url,data in (("GET-html", base+"/search?q="+qq, None),
                          ("POST-json", base+"/search", {"q":Q,"format":"json"})):
        r = fetch(url, data=data, headers={"User-Agent": UA_REAL}, timeout=12)
        if "err" in r: print("%-32s %-9s ERR %s" % (base,mode,r["err"])); continue
        b = r["body"]
        isjson = b[:1] in (b"{", b"[")
        ep = re.search(rb'name="endpoint" content="([^"]+)"', b)
        print("%-32s %-9s code=%s ct=%-28s len=%-7d json=%s endpoint=%s results_marker=%d" % (
            base, mode, r["code"], r["ct"][:28], r["len"], isjson,
            ep.group(1).decode() if ep else "-", b.count(b'class="result')))
        if isjson: open("out_searx_%s.json" % base.split("//")[1].split(".")[0], "wb").write(b)
    time.sleep(1)
