import netguard as N, re, html
# 1. real DNS rebinding names, allowlisted BY NAME so only the IP check can save us
P=N.Policy(allow_subdomains_of=("nip.io","localtest.me","wikipedia.org","wikimedia.org"))
for u in ("https://169.254.169.254.nip.io/latest/meta-data/","https://localtest.me/"):
    try: print("NOT BLOCKED:",u,N.fetch(u,P))
    except N.Blocked as e: print("blocked  :",u,"->",e)
    except N.FetchError as e: print("fetcherr :",u,"->",e)
# 2. a real fetch that must yield REAL CONTENT
r=N.fetch("https://en.wikipedia.org/wiki/Cat",P)
print(repr(r), "ctype",r.content_type,"charset",r.charset,"hops",r.hops)
txt=r.body.decode("utf-8","replace")
m=re.search(r"<p>(.{200,400}?)</p>",txt,re.S)
print("has <title>:", "<title>Cat - Wikipedia</title>" in txt or "Cat - Wikipedia" in txt)
print("first para snippet:", re.sub(r"<[^>]+>","",m.group(1))[:180].replace("\n"," ") if m else "NONE")
print("gzip actually used:", r.headers.get("Content-Encoding"))
