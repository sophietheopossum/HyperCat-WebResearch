from probe import *
qs = ["landlock seccomp sandbox","python urllib user agent","wayland compositor smithay",
      "prompt injection defense","rust ra_ap_syntax","quickshell qml"]
for i,q in enumerate(qs):
    for host,path in (("html.duckduckgo.com","/html/"),):
        url = "https://%s%s?q=%s" % (host,path,urllib.parse.quote(q))
        r = fetch(url, headers={"User-Agent": UA_REAL})
        n = r.get("body",b"").count(b"result__a")
        print("%-28s code=%s len=%s results=%d %.2fs" % (q[:28], r.get("code",r.get("err")), r.get("len"), n, r.get("dt",0)))
        time.sleep(4)
