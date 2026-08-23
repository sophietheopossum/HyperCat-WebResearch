from probe import *
Q = "landlock seccomp sandbox linux"
tests = [
 ("ddg-html GET no-UA",  "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(Q), None, {}),
 ("ddg-html GET realUA", "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(Q), None, {"User-Agent": UA_REAL}),
 ("ddg-html POST realUA","https://html.duckduckgo.com/html/", {"q": Q}, {"User-Agent": UA_REAL}),
 ("ddg-lite GET realUA", "https://lite.duckduckgo.com/lite/?q=" + urllib.parse.quote(Q), None, {"User-Agent": UA_REAL}),
 ("ddg-lite POST realUA","https://lite.duckduckgo.com/lite/", {"q": Q}, {"User-Agent": UA_REAL}),
 ("ddg-api json",        "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q=" + urllib.parse.quote(Q), None, {"User-Agent": UA_REAL}),
]
for tag, url, data, hdr in tests:
    r = fetch(url, data=data, headers=hdr)
    show(tag, r, 500)
    if "body" in r: open("out_%s.bin" % tag.replace(" ","_"), "wb").write(r["body"])
    time.sleep(2)
