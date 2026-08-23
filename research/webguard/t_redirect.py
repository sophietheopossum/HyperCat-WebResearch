import http.server, socketserver, threading, gzip, io, time, socket, sys
import netguard as N

BODY_HTML = b"<html><head><title>ok</title></head><body><p>real content here</p></body></html>"

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _send(self, code, headers, body=b""):
        self.send_response(code)
        for k,v in headers.items(): self.send_header(k,v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body: self.wfile.write(body)
    def do_GET(self):
        p = self.path
        port = self.server.server_address[1]
        if p == "/ok":              self._send(200, {"Content-Type":"text/html"}, BODY_HTML)
        elif p == "/meta":          self._send(302, {"Location":"http://169.254.169.254/latest/meta-data/"})
        elif p == "/file":          self._send(302, {"Location":"file:///etc/passwd"})
        elif p == "/offlist":       self._send(302, {"Location":"https://evil.example.com/x"})
        elif p == "/creds":         self._send(302, {"Location":"http://user:pw@127.0.0.1:%d/ok"%port})
        elif p == "/port":          self._send(302, {"Location":"http://127.0.0.1:22/ok"})
        elif p == "/rel":           self._send(302, {"Location":"/ok"})
        elif p == "/loopA":         self._send(302, {"Location":"/loopB"})
        elif p == "/loopB":         self._send(302, {"Location":"/loopA"})
        elif p.startswith("/chain"):
            n = int(p[6:] or 0);   self._send(302, {"Location":"/chain%d"%(n+1)})
        elif p == "/big":
            self.send_response(200); self.send_header("Content-Type","text/plain")
            self.send_header("Content-Length", str(10*1024*1024)); self.end_headers()
            for _ in range(160): self.wfile.write(b"A"*65536)
        elif p == "/bomb":
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as g: g.write(b"\0"*(200*1024*1024))
            z = buf.getvalue()
            self._send(200, {"Content-Type":"text/plain","Content-Encoding":"gzip"}, z)
        elif p == "/slow":
            self.send_response(200); self.send_header("Content-Type","text/plain")
            self.send_header("Content-Length","1000000"); self.end_headers()
            for _ in range(1000):
                try: self.wfile.write(b"B"*100); self.wfile.flush(); time.sleep(0.3)
                except Exception: return
        elif p == "/binary":        self._send(200, {"Content-Type":"application/octet-stream"}, b"\x00"*100)
        elif p == "/nolocation":    self._send(302, {})
        else:                       self._send(404, {"Content-Type":"text/plain"}, b"nope")

srv = socketserver.ThreadingTCPServer(("127.0.0.1",0), H)
srv.daemon_threads = True
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

def pol(**kw):
    p = N.Policy(allow_hosts=("127.0.0.1","localhost"), allow_ip_literals=True, allow_plain_http=True,
                 allowed_ports=(PORT,80,443), **kw)
    p.permit_ip_classes = ("127.0.0.0/8",)   # TEST SEAM: lets the fixture live on 127.0.0.1
    return p

B = "http://127.0.0.1:%d" % PORT
cases = [
 ("baseline /ok",            B+"/ok",     pol(), "expect 200"),
 ("302 -> metadata IP",      B+"/meta",   pol(), "expect Blocked"),
 ("302 -> file://",          B+"/file",   pol(), "expect Blocked"),
 ("302 -> off-allowlist",    B+"/offlist",pol(), "expect Blocked"),
 ("302 -> creds in URL",     B+"/creds",  pol(), "expect Blocked"),
 ("302 -> port 22",          B+"/port",   pol(), "expect Blocked"),
 ("302 -> relative /ok",     B+"/rel",    pol(), "expect 200"),
 ("redirect loop",           B+"/loopA",  pol(), "expect Blocked"),
 ("chain > max",             B+"/chain0", pol(max_redirects=3), "expect Blocked"),
 ("no Location",             B+"/nolocation", pol(), "expect FetchError"),
 ("binary content-type",     B+"/binary", pol(), "expect Blocked"),
 ("10MB body vs 1MB cap",    B+"/big",    pol(max_bytes=1024*1024), "expect truncated"),
 ("gzip bomb 200MB",         B+"/bomb",   pol(max_bytes=1024*1024), "expect truncated, fast"),
 ("slow drip vs 3s budget",  B+"/slow",   pol(total_timeout_s=3.0, read_timeout_s=2.0), "expect truncated/err"),
]
for name,url,p,exp in cases:
    t0=time.monotonic()
    try:
        r = N.fetch(url,p)
        out = "%s %d bytes trunc=%s hops=%d" % (r.status, len(r.body), r.truncated, len(r.hops))
    except N.Blocked as e:   out = "Blocked(%s)" % e
    except N.FetchError as e: out = "FetchError(%s)" % e
    except Exception as e:   out = "!! %s: %s" % (type(e).__name__, e)
    print("%-26s %-22s %-8.2fs %s" % (name, exp, time.monotonic()-t0, out))
srv.shutdown()
