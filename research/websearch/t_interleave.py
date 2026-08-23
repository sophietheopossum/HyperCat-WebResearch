import sys, time, urllib.parse, urllib.request, gzip, random; sys.path.insert(0,'.')
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
ACC="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
FIRST=[("User-Agent",UA),("Accept",ACC),("Accept-Language","en-GB,en;q=0.5"),("Accept-Encoding","gzip, deflate")]
LAST =[("Accept",ACC),("Accept-Language","en-GB,en;q=0.5"),("Accept-Encoding","gzip, deflate"),("User-Agent",UA)]
def get(q,pairs):
    req=urllib.request.Request("https://html.duckduckgo.com/html/?q="+urllib.parse.quote(q,safe=""))
    for k,v in pairs: req.add_header(k,v)
    try:
        r=urllib.request.urlopen(req,timeout=12); b=r.read()
    except Exception as e: return None,str(e)
    if (r.headers.get("Content-Encoding","") or "").lower()=="gzip":
        try: b=gzip.decompress(b)
        except Exception: pass
    return b.count(b"result__a"), r.status
words=["quantum","ferment","basalt","lantern","meadow","cobalt","zephyr","tundra","marmot","cinder",
       "willow","garnet","plover","thistle","onyx","harbor","juniper","pelican","saffron","vellum"]
random.seed(7)
res={"FIRST":[0,0],"LAST":[0,0]}
for i in range(10):
    q1 = "%s %s recipe history" % (random.choice(words), random.choice(words))
    q2 = "%s %s recipe history" % (random.choice(words), random.choice(words))
    for tag,pairs,q in (("FIRST",FIRST,q1),("LAST",LAST,q2)) if i%2==0 else (("LAST",LAST,q2),("FIRST",FIRST,q1)):
        hits,st = get(q,pairs)
        ok = bool(hits)
        res[tag][0 if ok else 1]+=1
        print("  round%-2d %-5s %-34s status=%s hits=%s"%(i,tag,q[:34],st,hits),flush=True)
        time.sleep(5)
print("FIRST ok=%d blocked=%d | LAST ok=%d blocked=%d"%(res["FIRST"][0],res["FIRST"][1],res["LAST"][0],res["LAST"][1]))
