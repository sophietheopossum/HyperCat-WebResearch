import sys, time, urllib.parse, urllib.request, gzip; sys.path.insert(0,'.')
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
ACC="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
def raw_get(url,pairs,timeout=10):
    req=urllib.request.Request(url)
    for k,v in pairs: req.add_header(k,v)
    r=urllib.request.urlopen(req,timeout=timeout); b=r.read()
    if (r.headers.get("Content-Encoding","") or "").lower()=="gzip":
        try: b=gzip.decompress(b)
        except Exception: pass
    return r.status,b
def run(tag,pairs,qs,gap=3):
    ok=0
    for q in qs:
        try:
            c,b=raw_get("https://html.duckduckgo.com/html/?q="+urllib.parse.quote(q,safe=""),pairs)
            hit=b.count(b"result__a"); ok+= (hit>0)
            print("  %-24s %-22s code=%s hits=%d"%(tag,q[:22],c,hit),flush=True)
        except Exception as e: print("  %-24s %-22s ERR %s"%(tag,q[:22],e),flush=True)
        time.sleep(gap)
    print("== %s: %d/%d\n"%(tag,ok,len(qs)),flush=True); time.sleep(10)
A=["kms atomic commit","gbm surface","wl_shm pool","libinput gestures","xkbcommon layout"]
B=["mesa iris driver","xe kernel driver","amdgpu reset","drm lease","vrr adaptive sync"]
# reverse order vs the previous run: UAlast first, then UAfirst
run("UAlast(all4)",[("Accept",ACC),("Accept-Language","en-GB,en;q=0.5"),("Accept-Encoding","gzip, deflate"),("User-Agent",UA)],A)
run("UAfirst(all4)",[("User-Agent",UA),("Accept",ACC),("Accept-Language","en-GB,en;q=0.5"),("Accept-Encoding","gzip, deflate")],B)
