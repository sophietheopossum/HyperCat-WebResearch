import sys, time, json; sys.path.insert(0,'.')
import backends
QS = [
 "landlock lsm abi 5 network rules","seccomp bpf user notification","how does tls 1.3 handshake work",
 "python urllib add_header order","rust ra_ap_syntax code action","wayland ext-image-copy-capture protocol",
 "what is prompt injection","best sourdough hydration ratio","capital of mongolia population",
 "openssl 3.6 release notes changes","nginx reverse proxy websocket config","btrfs subvolume snapshot rollback",
 "zig comptime metaprogramming guide","postgres autovacuum tuning","smithay compositor tutorial",
 "quickshell qml singleton import","nvidia muxless laptop rtd3 suspend","xdg-output logical position scale",
 "systemd user socket activation example","flatpak override filesystem permission","gzip deflate content-encoding urllib",
 "cloudflare bot management fingerprint","json lines ndjson spec","landlock vs seccomp comparison",
 "arch linux pacman hooks","fish shell abbreviation syntax","wl_fixed_t rounding precision",
 "ext-session-lock-v1 protocol","dmabuf feedback tranche","drm atomic modeset commit",
]
def bench(name, fn, retries=1, gap=3.0, **kw):
    ok=blk=err=0; empt=0; lat=[]; sample=None
    for q in QS:
        for a in range(retries+1):
            t0=time.time()
            try:
                rs=fn(q, **kw); lat.append(time.time()-t0)
                if rs: ok+=1
                else: empt+=1
                if sample is None and rs: sample=rs[0]
                break
            except backends.Blocked as e:
                if a==retries: blk+=1
                else: time.sleep(4)
            except Exception as e:
                if a==retries: err+=1; print("   ERR %-30s %s: %s"%(q[:30],type(e).__name__,e))
                else: time.sleep(2)
        time.sleep(1.0)
    med = sorted(lat)[len(lat)//2] if lat else -1
    print("%-16s ok=%-3d empty=%-3d blocked=%-3d err=%-3d medlat=%.2fs" % (name, ok, empt, blk, err, med), flush=True)
    if sample: print("   sample: %s" % json.dumps(sample)[:220], flush=True)
    bench(name, fn, **kw)
    time.sleep(10)
