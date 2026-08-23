from probe import *
QS = ["landlock","seccomp bpf","wayland protocols","python asyncio","rust borrow checker",
      "sourdough","mongolia","openssl","nginx config","systemd timer","gpu driver",
      "vim keybindings","postgres index","docker compose","zig language","haskell monad",
      "kernel module","bash script","json parser","tls handshake"]
ok=to=err=0; lat=[]
for q in QS:
    r = fetch("https://api.marginalia.nu/public/search/"+urllib.parse.quote(q),
              headers={"User-Agent":"HyperCatWebSearch/0.1"}, timeout=6)
    if "err" in r:
        if "Timeout" in r["err"]: to+=1
        else: err+=1
        print("  %-20s %s" % (q, r["err"]))
    else:
        ok+=1; lat.append(r["dt"])
    time.sleep(0.3)
print("ok=%d timeout=%d othererr=%d  lat min/med/max=%.2f/%.2f/%.2f" %
      (ok,to,err,min(lat),sorted(lat)[len(lat)//2],max(lat)))
