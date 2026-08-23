from probe import *
Q = "landlock seccomp sandbox"
qq = urllib.parse.quote(Q)
UA_TOOL = "HyperCatWebSearch/0.1 (+local agent tool)"
tests = [
 ("wikipedia-apiphp", "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=%s&srlimit=5&format=json&formatversion=2" % qq, {"User-Agent": UA_TOOL}),
 ("wikipedia-rest",   "https://en.wikipedia.org/w/rest.php/v1/search/page?q=%s&limit=5" % qq, {"User-Agent": UA_TOOL}),
 ("wikipedia-noUA",   "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=%s&srlimit=5&format=json&formatversion=2" % qq, {}),
 ("mojeek-html",      "https://www.mojeek.com/search?q=%s" % qq, {"User-Agent": UA_REAL}),
 ("marginalia-html",  "https://search.marginalia.nu/search?query=%s" % qq, {"User-Agent": UA_REAL}),
 ("marginalia-old",   "https://old-search.marginalia.nu/search?query=%s" % qq, {"User-Agent": UA_REAL}),
]
for tag,url,hdr in tests:
    r = fetch(url, headers=hdr)
    show(tag, r, 600)
    if "body" in r: open("out_%s.bin"%tag,"wb").write(r["body"])
    time.sleep(1.5)
