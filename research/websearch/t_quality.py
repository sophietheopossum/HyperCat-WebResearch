import sys, time, json; sys.path.insert(0,'.')
import backends
QS=["how do I set a user agent in python urllib",
    "landlock abi version 5 network rules",
    "duckduckgo html rate limit 202 anomaly",
    "what is the population of ulaanbaatar",
    "smithay wayland compositor example"]
for q in QS:
    print("\n############ %s" % q)
    for name in ("ddg_html","marginalia","mwmbl","wiby"):
        try:
            rs=backends.ALL[name](q, n=3)
            print(" -- %s (%d)"%(name,len(rs)))
            for r in rs:
                print("    %-58s | %s" % (r["title"][:58], r["url"][:70]))
                print("      snip(%d): %s" % (len(r["snippet"]), r["snippet"][:150]))
        except Exception as e:
            print(" -- %s FAILED %s: %s"%(name,type(e).__name__,str(e)[:90]))
        time.sleep(2.5)
    time.sleep(4)
