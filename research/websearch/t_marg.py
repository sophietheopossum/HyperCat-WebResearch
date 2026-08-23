from probe import *
QS = ["landlock seccomp sandbox","python urllib user agent","wayland compositor smithay",
      "prompt injection defense llm","rust ra_ap_syntax","quickshell qml",
      "how to make sourdough starter","what is the capital of mongolia","nvidia rtd3 muxless laptop",
      "openssl 3.6 release notes"]
UA_TOOL = "HyperCatWebSearch/0.1"
for q in QS:
    url = "https://api.marginalia.nu/public/search/" + urllib.parse.quote(q)
    r = fetch(url, headers={"User-Agent": UA_TOOL})
    if "err" in r: print("%-34s ERR %s" % (q[:34], r["err"])); continue
    try:
        d = json.loads(r["body"]); n = len(d.get("results",[]))
        top = d["results"][0]["url"][:70] if n else "-"
    except Exception as e:
        n, top = -1, "PARSE %s :: %s" % (e, r["body"][:80])
    print("%-34s code=%s n=%-3s %.2fs  %s" % (q[:34], r["code"], n, r["dt"], top))
    time.sleep(0.4)
# no-UA probe
r = fetch("https://api.marginalia.nu/public/search/test", headers={})
print("no-UA(default urllib):", r.get("code"), r.get("len"), r.get("err",""))
