import socket, time, threading, http.server, socketserver
import netguard as N

# --- 1. mixed DNS answer (the rebinder's best move): one public + one internal -> refuse the NAME
def mixed(host, port, timeout):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
P = N.Policy(allow_hosts=("example.com",))
try:
    N.resolve_and_check("example.com", 443, P, _resolver=mixed); print("FAIL: mixed answer accepted")
except N.Blocked as e: print("mixed answer  ->", e)

# --- 2. exactly ONE resolution per hop, and the connect goes to the vetted sockaddr (no re-resolve)
class H(http.server.BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self, format, *args): pass
    def do_GET(self):
        b=b"<html><p>pinned</p></html>"
        self.send_response(200); self.send_header("Content-Type","text/html")
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
srv=socketserver.ThreadingTCPServer(("127.0.0.1",0),H); srv.daemon_threads=True
PORT=srv.server_address[1]
threading.Thread(target=srv.serve_forever,daemon=True).start()

calls=[]
def flipflop(host, port, timeout):
    """A rebinding resolver: 1st answer good, EVERY later answer is the metadata address."""
    calls.append(host)
    if len(calls)==1:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", PORT))]
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

p=N.Policy(allow_hosts=("evil-rebinder.test",), allow_plain_http=True, allowed_ports=(PORT,))
p.permit_ip_classes=("127.0.0.0/8",)
r=N.fetch("http://evil-rebinder.test:%d/x"%PORT, p, _resolver=flipflop)
print("pinned fetch  ->", r.status, r.body, "| resolver calls:", len(calls))

# peer check: patch connect to record getpeername
peers=[]
orig=N._PinnedHTTPConnection.connect
def spy(self):
    orig(self); peers.append(self.sock.getpeername())
N._PinnedHTTPConnection.connect=spy
calls.clear()
r=N.fetch("http://evil-rebinder.test:%d/x"%PORT, p, _resolver=flipflop)
print("connected peer:", peers, "(vetted addr, not a second lookup)")
N._PinnedHTTPConnection.connect=orig
srv.shutdown()

# --- 3. TLS still verifies through the pinned path (real hosts)
tp=N.Policy(allow_subdomains_of=("badssl.com",))
for h in ("expired","self-signed","wrong.host","untrusted-root"):
    u="https://%s.badssl.com/"%h
    try:
        rr=N.fetch(u,tp); print("%-16s -> NOT REFUSED %s %d bytes"%(h,rr.status,len(rr.body)))
    except N.FetchError as e: print("%-16s -> %s"%(h,str(e)[:110]))
    except N.Blocked as e: print("%-16s -> Blocked %s"%(h,e))
try:
    rr=N.fetch("https://badssl.com/",tp); print("%-16s -> %s %d bytes (control: valid cert works)"%("badssl.com",rr.status,len(rr.body)))
except Exception as e: print("control FAILED:",type(e).__name__,e)
