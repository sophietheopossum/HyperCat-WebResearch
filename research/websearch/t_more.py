from probe import *
Q = "landlock seccomp sandbox"; qq = urllib.parse.quote(Q)
UA_TOOL = "HyperCatWebSearch/0.1 (+local agent tool)"
tests = [
 ("marginalia-api", "https://api.marginalia.nu/public/search/%s" % qq, None, {"User-Agent": UA_TOOL}),
 ("yep-api",        "https://api.yep.com/fs/2/search?client=web&gl=US&limit=20&no_correct=false&q=%s&safeSearch=off&type=web" % qq, None, {"User-Agent": UA_REAL}),
 ("stract-api",     "https://stract.com/beta/api/search", json.dumps({"query": Q}).encode(), {"User-Agent": UA_REAL, "Content-Type":"application/json"}),
 ("searxng-inetol", "https://search.inetol.net/search?q=%s&format=json" % qq, None, {"User-Agent": UA_REAL}),
 ("searxng-priv",   "https://priv.au/search?q=%s&format=json" % qq, None, {"User-Agent": UA_REAL}),
 ("searxng-opnxng", "https://opnxng.com/search?q=%s&format=json" % qq, None, {"User-Agent": UA_REAL}),
 ("searxng-tiekoe", "https://searx.tiekoetter.com/search?q=%s&format=json" % qq, None, {"User-Agent": UA_REAL}),
 ("searxng-paulgo", "https://paulgo.io/search?q=%s&format=json" % qq, None, {"User-Agent": UA_REAL}),
]
for tag,url,data,hdr in tests:
    r = fetch(url, data=data, headers=hdr)
    show(tag, r, 350)
    if "body" in r: open("out_%s.bin"%tag,"wb").write(r["body"])
    time.sleep(1.5)
