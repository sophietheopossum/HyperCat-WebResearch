import sys, os, socket, ssl, time, threading, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
def t(name, fn):
    try:
        print("PASS %-28s %s" % (name, fn()), flush=True)
    except BaseException as e:
        print("FAIL %-28s %s: %s" % (name, type(e).__name__, str(e)[:120]), flush=True)

print("env vars visible:", len(os.environ), dict(list(os.environ.items())[:5]), flush=True)
print("argv:", sys.argv, flush=True)
t("thread creation", lambda: (lambda th: (th.start(), th.join(), "ok")[-1])(threading.Thread(target=lambda: None)))
t("open /etc/resolv.conf", lambda: open("/etc/resolv.conf").readline().strip())
t("open /etc/ssl/certs CA", lambda: str(len(open("/etc/ssl/certs/ca-certificates.crt","rb").read(4096))) + " bytes")
t("open /home (should fail)", lambda: open("/home/seirra/.bashrc").readline())
t("open /run/systemd/resolve", lambda: str(os.listdir("/run/systemd/resolve")))
t("write /tmp (should fail)", lambda: open("/tmp/jailprobe","w").write("x"))
t("socket(AF_INET)", lambda: str(socket.socket(socket.AF_INET, socket.SOCK_STREAM)).split(",")[0])
t("getaddrinfo wikipedia", lambda: str(sorted({a[4][0] for a in socket.getaddrinfo("en.wikipedia.org",443,0,socket.SOCK_STREAM)})))
t("ssl default context CAs", lambda: str(ssl.create_default_context().cert_store_stats()))
def guarded():
    import netguard as N
    P = N.Policy(allow_subdomains_of=("wikipedia.org",), max_bytes=256*1024)
    r = N.fetch("https://en.wikipedia.org/wiki/Cat", P)
    ok = b"<title>Cat" in r.body or b"Cat - Wikipedia" in r.body
    return "%s %d bytes trunc=%s real-content=%s" % (r.status, len(r.body), r.truncated, ok)
t("netguard fetch (real TLS)", guarded)
def blocked():
    import netguard as N
    P = N.Policy(allow_subdomains_of=("nip.io",))
    try:
        N.fetch("https://169.254.169.254.nip.io/latest/meta-data/", P); return "NOT BLOCKED (bad)"
    except N.Blocked as e: return "Blocked: %s" % e
t("metadata via public DNS", blocked)
