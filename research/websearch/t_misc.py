from probe import *
Q = "landlock seccomp sandbox"
qq = urllib.parse.quote(Q)
UA_TOOL = "HyperCatWebSearch/0.1 (+local agent tool)"
tests = [
 ("wikipedia-apiphp", "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=%s&srlimit=5&format=json&formatversion=2" % qq, None, {"User-Agent": UA_TOOL}),
 ("wikipedia-rest",   "https://en.wikipedia.org/w/rest.php/v1/search/page?q=%s&limit=5" % qq, None, {"User-Agent": UA_TOOL}),
 ("wiby-json",        "https://wiby.me/json/?q=%s" % qq, None, {"User-Agent": UA_TOOL}),
 ("mojeek-html",      "https://www.mojeek.com/search?q=%s" % qq, None, {"User-Agent": UA_REAL}),
 ("marginalia-html",  "https://search.marginalia.nu/search?query=%s" % qq, None, {"User-Agent": UA_REAL}),
 ("hn-algolia",       "https://hn.algolia.com/api/v1/search?query=%s&hitsPerPage=5" % qq, None, {"User-Agent": UA_TOOL}),
 ("stackexchange",    "https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&q=%s&site=stackoverflow&pagesize=5&filter=withbody" % qq, None, {"User-Agent": UA_TOOL}),
 ("searx-be-json",    "https://searx.be/search?q=%s&format=json" % qq, None, {"User-Agent": UA_REAL}),
 ("startpage",        "https://www.startpage.com/sp/search?query=%s" % qq, None, {"User-Agent": UA_REAL}),
 ("ecosia",           "https://www.ecosia.org/search?q=%s" % qq, None, {"User-Agent": UA_REAL}),
 ("brave",            "https://search.brave.com/search?q=%s" % qq, None, {"User-Agent": UA_REAL}),
]
for tag,url,data,hdr in tests:
    r = fetch(url, data=data, headers=hdr)
    show(tag, r, 300)
    if "body" in r: open("out_%s.bin"%tag,"wb").write(r["body"])
    time.sleep(1.5)
