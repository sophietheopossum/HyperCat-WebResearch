import re
from probe import *
Q="landlock seccomp sandbox"; qq=urllib.parse.quote(Q)
BROWSER = {"User-Agent": UA_REAL,
  "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "Accept-Language":"en-GB,en;q=0.5", "Connection":"keep-alive",
  "Upgrade-Insecure-Requests":"1","Sec-Fetch-Dest":"document","Sec-Fetch-Mode":"navigate",
  "Sec-Fetch-Site":"same-origin","Sec-Fetch-User":"?1","DNT":"1"}
for base in ["https://search.inetol.net","https://priv.au","https://searx.tiekoetter.com","https://baresearch.org"]:
    for mode,url,data in (("GET",base+"/search?q="+qq,None), ("POST",base+"/search",{"q":Q})):
        r = fetch(url, data=data, headers=dict(BROWSER, Referer=base+"/"), timeout=15)
        if "err" in r: print("%-28s %s ERR %s"%(base,mode,r["err"])); continue
        b=r["body"]
        ep=re.search(rb'name="endpoint" content="([^"]+)"',b)
        print("%-28s %s code=%s len=%-7d endpoint=%-8s urlcls=%d article=%d" % (base,mode,r["code"],r["len"],
              ep.group(1).decode() if ep else "-", b.count(b'class="result'), b.count(b'<article')))
        open("out_sx_%s_%s.bin"%(base.split('//')[1].split('.')[0],mode),"wb").write(b)
    time.sleep(1)
