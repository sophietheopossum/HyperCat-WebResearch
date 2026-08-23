import socket, threading, http.server, socketserver, time
import netguard as N

# A) rebinding ACROSS a redirect: hop1 resolves good, hop2 (same host) flips to the metadata IP
class H(http.server.BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*a): pass
    def do_GET(self):
        if self.path=="/hop": self.send_response(302); self.send_header("Location","/final"); self.send_header("Content-Length","0"); self.end_headers()
        elif self.path=="/chunked":
            self.send_response(200); self.send_header("Content-Type","text/plain")
            self.send_header("Transfer-Encoding","chunked"); self.end_headers()
            try:
                for _ in range(300):
                    d=b"C"*65536; self.wfile.write(b"%x\r\n"%len(d)+d+b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            except Exception: pass
        else:
            b=b"<p>final</p>"; self.send_response(200); self.send_header("Content-Type","text/html")
            self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_HEAD(self):
        self.send_response(200); self.send_header("Content-Type","text/html"); self.send_header("Content-Length","12"); self.end_headers()

srv=socketserver.ThreadingTCPServer(("127.0.0.1",0),H); srv.daemon_threads=True
PORT=srv.server_address[1]; threading.Thread(target=srv.serve_forever,daemon=True).start()
n=[0]
def flip(host,port,timeout):
    n[0]+=1
    if n[0]==1: return [(socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",PORT))]
    return [(socket.AF_INET,socket.SOCK_STREAM,6,"",("169.254.169.254",port))]
p=N.Policy(allow_hosts=("rebind.test",),allow_plain_http=True,allowed_ports=(PORT,),max_bytes=512*1024)
p.permit_ip_classes=("127.0.0.0/8",)
try:
    r=N.fetch("http://rebind.test:%d/hop"%PORT,p,_resolver=flip); print("FAIL rebind-on-redirect:",r)
except N.Blocked as e: print("rebind on redirect hop2 ->",e)

p2=N.Policy(allow_hosts=("127.0.0.1",),allow_ip_literals=True,allow_plain_http=True,allowed_ports=(PORT,),max_bytes=512*1024)
p2.permit_ip_classes=("127.0.0.0/8",)
t0=time.monotonic(); r=N.fetch("http://127.0.0.1:%d/chunked"%PORT,p2)
print("chunked no Content-Length -> %d bytes trunc=%s in %.2fs (cap 512K)"%(len(r.body),r.truncated,time.monotonic()-t0))
r=N.fetch("http://127.0.0.1:%d/x"%PORT,p2,method="HEAD"); print("HEAD ->",r.status,len(r.body),"bytes")
srv.shutdown()

# B) a REAL cross-host redirect chain on the public internet
pw=N.Policy(allow_subdomains_of=("wikipedia.org",))
try:
    r=N.fetch("https://wikipedia.org/wiki/Cat",pw); print("real redirect ->",r.status,r.url,"hops",r.hops)
except Exception as e: print("real redirect ->",type(e).__name__,e)
# C) same chain with ONLY the first host allowlisted: the redirect must be refused
pn=N.Policy(allow_hosts=("wikipedia.org",))
try:
    r=N.fetch("https://wikipedia.org/wiki/Cat",pn); print("FAIL escaped allowlist ->",r.url)
except N.Blocked as e: print("redirect off allowlist ->",e)
