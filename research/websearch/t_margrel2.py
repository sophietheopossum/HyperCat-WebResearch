from probe import *
QS = ["seccomp bpf","python asyncio","rust borrow checker","openssl","systemd timer",
      "vim keybindings","postgres index","haskell monad","bash script","json parser"]
print("--- same queries, 5s apart, 8s timeout ---")
ok=to=0
for q in QS:
    r = fetch("https://api.marginalia.nu/public/search/"+urllib.parse.quote(q),
              headers={"User-Agent":"HyperCatWebSearch/0.1"}, timeout=8)
    if "err" in r: to+=1; print("  TIMEOUT %-20s %.1fs" % (q, r["dt"]))
    else: ok+=1; print("  ok      %-20s %.2fs n=%d" % (q, r["dt"], len(json.loads(r["body"]).get("results",[]))))
    time.sleep(5)
print("ok=%d timeout=%d" % (ok,to))
