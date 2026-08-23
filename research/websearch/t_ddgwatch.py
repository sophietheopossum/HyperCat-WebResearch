from probe import *
import datetime
qq = urllib.parse.quote("landlock seccomp sandbox")
for i in range(14):
    r = fetch("https://html.duckduckgo.com/html/?q="+qq, headers={"User-Agent": UA_REAL})
    n = r.get("body",b"").count(b"result__a")
    print("%s t+%dm code=%s len=%s results=%d" % (datetime.datetime.now().strftime("%H:%M:%S"), i*3,
          r.get("code", r.get("err")), r.get("len"), n), flush=True)
    time.sleep(180)
