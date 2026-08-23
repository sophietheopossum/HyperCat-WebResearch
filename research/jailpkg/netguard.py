"""netguard - in-process egress guard for a HyperCat managed (Python) tool.

WHY THIS EXISTS: permissions.egress_hosts is declared INTENT in v1. hc_confine's own header
says it: "SSRF/egress is NOT enforced here (a raw connect() to any IP is allowed at this
floor)". The host enforces per-host policy for ITS OWN traffic (hc_policy inside hc_http);
a third-party tool gets none of that. So the tool is the only place a host allowlist can
live, and it must survive redirects, DNS rebinding and v4-in-v6 spellings by itself.

Structure mirrors app/policy/src/hc_policy.cpp (allow-only-known-good, every v4-in-v6
embedding unwrapped) so the two agree on what "internal" means.

stdlib only. Threads are used for one thing (a bounded getaddrinfo), which the MANAGED
floor permits (HC_CONFINE_SYSCALL_MANAGED_RUNTIME allows clone).
"""

import http.client
import ipaddress
import socket
import ssl
import threading
import time
import zlib
from urllib.parse import urlsplit, urlunsplit, urljoin

__all__ = ["Policy", "Blocked", "FetchError", "Response", "classify_ip", "resolve_and_check", "fetch"]


class Blocked(Exception):
    """A policy refusal. The message is safe to show the model/operator."""


class FetchError(Exception):
    """A transport/protocol failure (DNS down, TLS failure, truncation, timeout)."""


# ---------------------------------------------------------------- policy

class Policy:
    def __init__(
        self,
        allow_hosts=(),                 # exact hostnames, lowercase, no trailing dot
        allow_subdomains_of=(),         # a host matches if it == d or endswith("." + d)
        allow_plain_http=False,         # https-only by default; http is a downgrade AND a plaintext leak
        allow_ip_literals=False,        # an IP-literal URL never matches a named allowlist -> keep False
        allowed_ports=(80, 443),
        max_redirects=5,
        max_bytes=2 * 1024 * 1024,      # cap on DECODED body bytes (also caps the compressed stream)
        total_timeout_s=20.0,           # one deadline across DNS + every hop + the body read
        connect_timeout_s=6.0,
        read_timeout_s=8.0,
        dns_timeout_s=5.0,
        allow_content_types=("text/html", "text/plain", "application/xhtml+xml",
                             "application/json", "application/xml", "text/xml"),
        user_agent="HyperCat-websearch/0.1 (+local tool)",
    ):
        self.allow_hosts = tuple(h.lower().rstrip(".") for h in allow_hosts)
        self.allow_subdomains_of = tuple(h.lower().rstrip(".") for h in allow_subdomains_of)
        self.allow_plain_http = allow_plain_http
        self.allow_ip_literals = allow_ip_literals
        self.allowed_ports = tuple(allowed_ports)
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes
        self.total_timeout_s = total_timeout_s
        self.connect_timeout_s = connect_timeout_s
        self.read_timeout_s = read_timeout_s
        self.dns_timeout_s = dns_timeout_s
        self.allow_content_types = tuple(allow_content_types)
        self.user_agent = user_agent
        # TEST SEAM ONLY. Never set in the shipped tool: it disables the IP-class check.
        self.permit_ip_classes = ()

    def host_allowed(self, host):
        if host in self.allow_hosts:
            return True
        for d in self.allow_subdomains_of:
            if host == d or host.endswith("." + d):
                return True
        return False


# ---------------------------------------------------------------- IP classification

_V4_DENY = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",         # this network / unspecified
    "10.0.0.0/8",
    "100.64.0.0/10",     # CGNAT - also Alibaba metadata 100.100.100.200
    "127.0.0.0/8",
    "169.254.0.0/16",    # link-local: 169.254.169.254 (AWS/GCP/Azure/DO metadata)
    "172.16.0.0/12",
    "192.0.0.0/24",      # IETF protocol assignments (incl. 192.0.0.192)
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",   # documentation
    "192.88.99.0/24",    # 6to4 relay anycast
    "192.168.0.0/16",
    "198.18.0.0/15",     # benchmarking
    "224.0.0.0/4",       # multicast
    "240.0.0.0/4",       # reserved, incl. 255.255.255.255
))

_V6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")
_V6_DOC_2001 = ipaddress.ip_network("2001:db8::/32")
_V6_DOC_3FFF = ipaddress.ip_network("3fff::/20")
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def _classify_v4(ip):
    for net in _V4_DENY:
        if ip in net:
            return "deny:" + str(net)
    if not ip.is_global:            # belt-and-braces: IANA special-purpose per the stdlib registry
        return "deny:not-global"
    return "ok"


def classify_ip(ip):
    """'ok', or 'deny:<why>'. ALLOW-ONLY-KNOWN-GOOD: anything not provably global unicast is denied.

    Empirically (python 3.14) neither is_private nor is_global alone is safe:
      224.0.0.1 is_global=True, ff02::1 is_global=True, 64:ff9b::a9fe:a9fe is_global=True,
      ::a9fe:a9fe is_global=True, and 100.100.100.200 is_private=False.
    So: explicit deny-nets for v4, and for v6 unwrap every v4 embedding then require 2000::/3.
    """
    if isinstance(ip, str):
        if "%" in ip:
            return "deny:scoped-address"     # fe80::1%eth0 - link-local by construction
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError:
            return "deny:unparseable"
    if ip.version == 4:
        return _classify_v4(ip)

    if getattr(ip, "scope_id", None):
        return "deny:scoped-address"
    packed = ip.packed
    if ip == ipaddress.ip_address("::"):
        return "deny:unspecified"
    if ip == ipaddress.ip_address("::1"):
        return "deny:loopback"
    # --- every v4-in-v6 spelling folds back into the v4 classifier ---
    if ip.ipv4_mapped is not None:                       # ::ffff:a.b.c.d
        return _rewrap(_classify_v4(ip.ipv4_mapped), "v4-mapped")
    if packed[:12] == b"\x00" * 12:                      # ::a.b.c.d  (v4-compatible, deprecated)
        return _rewrap(_classify_v4(ipaddress.IPv4Address(packed[12:])), "v4-compatible")
    for net in _NAT64:
        if ip in net:                                    # 64:ff9b::/96, 64:ff9b:1::/48
            return _rewrap(_classify_v4(ipaddress.IPv4Address(packed[12:])), "nat64")
    if ip.sixtofour is not None:                         # 2002:V4::/16
        return _rewrap(_classify_v4(ip.sixtofour), "6to4")
    if ip.teredo is not None:                            # 2001::/32 - deny the tunnel outright
        return "deny:teredo"
    # --- native v6 specials ---
    if packed[0] == 0xFE and (packed[1] & 0xC0) == 0x80:
        return "deny:link-local"                          # fe80::/10
    if (packed[0] & 0xFE) == 0xFC:
        return "deny:unique-local"                        # fc00::/7
    if packed[0] == 0xFF:
        return "deny:multicast"                           # ff00::/8
    for doc in (_V6_DOC_2001, _V6_DOC_3FFF):     # documentation prefixes: RFC 3849, RFC 9637
        if ip in doc:
            return "deny:documentation"
    if ip not in _V6_GLOBAL_UNICAST:
        return "deny:not-global-unicast"
    return "ok"


def _rewrap(verdict, how):
    return verdict if verdict == "ok" else verdict + " (via " + how + ")"


# ---------------------------------------------------------------- URL validation

def validate_url(url, policy):
    """-> (scheme, host, port, path_with_query). Raises Blocked. Purely syntactic + allowlist."""
    if not isinstance(url, str) or len(url) > 2048:
        raise Blocked("url missing or too long")
    if any(c in url for c in "\r\n\t") or any(ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        raise Blocked("url contains control characters")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise Blocked("scheme %r is not http(s)" % (scheme or "<none>"))
    if scheme == "http" and not policy.allow_plain_http:
        raise Blocked("plaintext http is refused (https only)")
    netloc = parts.netloc
    if "@" in netloc:
        raise Blocked("credentials in the URL are refused")
    if parts.username or parts.password:
        raise Blocked("credentials in the URL are refused")
    try:
        host = parts.hostname                # already lowercased + brackets stripped by urlsplit
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as e:
        raise Blocked("malformed host/port: %s" % e)
    if not host:
        raise Blocked("no host in url")
    host = host.rstrip(".")                  # "example.com." == "example.com" for matching
    if port not in policy.allowed_ports:
        raise Blocked("port %d is not allowed" % port)
    # IDN -> punycode, so the allowlist compares the same bytes the DNS + Host header will carry.
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as e:
            raise Blocked("hostname is not encodable as IDNA: %s" % e)
    host = host.lower()
    if len(host) > 253:
        raise Blocked("hostname too long")
    is_literal = _is_ip_literal(host)
    if is_literal and not policy.allow_ip_literals:
        raise Blocked("IP-literal URLs are refused (host allowlist is by name)")
    if not policy.host_allowed(host):
        raise Blocked("host %r is not on the tool's allowlist" % host)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return scheme, host, port, path


def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- resolve + check

def _getaddrinfo_bounded(host, port, timeout):
    """getaddrinfo(3) has no timeout argument and can block for resolv.conf's whole retry budget.
    Run it on a daemon thread and abandon it on our own deadline (the managed floor allows clone)."""
    box = {}

    def work():
        try:
            box["r"] = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        except BaseException as e:          # noqa: BLE001 - reported, not swallowed
            box["e"] = e

    t = threading.Thread(target=work, daemon=True, name="netguard-dns")
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise FetchError("DNS lookup for %s timed out after %.1fs" % (host, timeout))
    if "e" in box:
        raise FetchError("DNS lookup for %s failed: %s" % (host, box["e"]))
    return box.get("r") or []


def resolve_and_check(host, port, policy, _resolver=None):
    """Resolve, then vet EVERY answer. -> list of (family, sockaddr, ip_str).

    Fail-closed on a MIXED answer: if any address is internal the whole name is refused. A
    rebinding attacker's ideal answer is one good + one bad address, so 'connect to a good one'
    is not enough - the name itself is hostile.
    """
    infos = (_resolver or _getaddrinfo_bounded)(host, port, policy.dns_timeout_s)
    if not infos:
        raise FetchError("DNS returned no addresses for %s" % host)
    vetted = []
    for family, _stype, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise Blocked("unexpected address family %r for %s" % (family, host))
        ip_str = sockaddr[0]
        verdict = classify_ip(ip_str)
        if verdict != "ok" and not any(tok in verdict for tok in policy.permit_ip_classes):
            raise Blocked("%s resolves to a non-public address %s (%s)" % (host, ip_str, verdict))
        vetted.append((family, sockaddr, ip_str))
    return vetted


# ---------------------------------------------------------------- pinned connection

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """http.client, but connected to an IP WE already vetted - no second resolution.

    The gap this closes: validate(host) -> resolve(host) -> [connect(host)] would let the
    resolver hand a different (internal) address to the connect. We connect to the exact
    sockaddr we classified, and pass the NAME as server_hostname so SNI + certificate
    verification still bind to the name the allowlist approved.
    """

    def __init__(self, host, port, family, sockaddr, timeout, context):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pin_family = family
        self._pin_sockaddr = sockaddr

    def connect(self):
        sock = socket.socket(self._pin_family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._pin_sockaddr)
        except OSError:
            sock.close()
            raise
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, family, sockaddr, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self._pin_family = family
        self._pin_sockaddr = sockaddr

    def connect(self):
        sock = socket.socket(self._pin_family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._pin_sockaddr)
        except OSError:
            sock.close()
            raise
        self.sock = sock


def _tls_context():
    ctx = ssl.create_default_context()      # verify + check_hostname on; CAs from /etc/ssl (Landlock grants /etc ro)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return ctx


# ---------------------------------------------------------------- fetch

class Response:
    def __init__(self, url, status, headers, body, content_type, charset, hops, truncated):
        self.url = url
        self.status = status
        self.headers = headers
        self.body = body
        self.content_type = content_type
        self.charset = charset
        self.hops = hops                 # every URL walked, in order - show this to the operator
        self.truncated = truncated

    def __repr__(self):
        return "<Response %s %s %d bytes hops=%d trunc=%s>" % (
            self.status, self.url, len(self.body), len(self.hops), self.truncated)


def fetch(url, policy, method="GET", _resolver=None):
    """GET a URL under the policy, following redirects MANUALLY so every hop is re-validated.

    The loop is the point. urllib/requests-style automatic redirect following re-parses and
    re-resolves internally, so a 302 from an allowlisted host to http://169.254.169.254/ is
    followed before any of our checks see it. Here each hop runs validate_url + resolve_and_check
    again, from scratch, before a single byte is sent.
    """
    if method not in ("GET", "HEAD"):
        raise Blocked("method %r is not allowed" % method)
    deadline = time.monotonic() + policy.total_timeout_s
    hops = []
    current = url
    for hop in range(policy.max_redirects + 1):
        if deadline - time.monotonic() <= 0:
            raise FetchError("overall timeout after %d hop(s)" % hop)
        scheme, host, port, path = validate_url(current, policy)      # <- full re-check on EVERY hop
        hostport = host if port in (80, 443) else "%s:%d" % (host, port)
        hops.append("%s://%s%s" % (scheme, hostport, path))
        vetted = resolve_and_check(host, port, policy, _resolver=_resolver)

        headers = {
            "Host": hostport,
            "User-Agent": policy.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,text/plain;q=0.8,*/*;q=0.1",
            "Accept-Encoding": "gzip",       # NOT br/zstd: no stdlib decoder for either
            "Accept-Language": "en",
            "Connection": "close",           # one connection per hop; nothing is reused across hops
        }
        conn = resp = None
        errs = []
        for family, sockaddr, ip_str in vetted:      # every vetted address is safe to try (deny-if-any-bad)
            c = _make_conn(scheme, host, port, family, sockaddr, policy, deadline)
            try:
                c.request(method, path, headers=headers)
                c.sock.settimeout(min(policy.read_timeout_s, max(0.1, deadline - time.monotonic())))
                r = c.getresponse()
            except (OSError, http.client.HTTPException) as e:
                try:
                    c.close()
                except OSError:
                    pass
                errs.append("%s: %s: %s" % (ip_str, type(e).__name__, e))
                continue
            conn, resp = c, r
            break
        if resp is None:
            raise FetchError("could not reach %s (%s)" % (host, "; ".join(errs)))

        try:
            status = resp.status
            if status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                if not loc:
                    raise FetchError("redirect %d with no Location" % status)
                if len(loc) > 2048:
                    raise Blocked("redirect Location is too long")
                nxt = urljoin(current, loc.strip())
                if nxt in hops or nxt == current:
                    raise Blocked("redirect loop")
                current = nxt
                continue                                  # -> next iteration re-validates everything
            ctype, charset = _split_content_type(resp.getheader("Content-Type") or "")
            if ctype and policy.allow_content_types and ctype not in policy.allow_content_types:
                raise Blocked("content-type %r is not one this tool reads" % ctype)
            declared = resp.getheader("Content-Length")
            if declared and declared.isdigit() and int(declared) > policy.max_bytes * 8:
                raise Blocked("declared body of %s bytes is far over the cap" % declared)
            try:
                body, truncated = _read_capped(resp, conn, policy, deadline)
            except (OSError, http.client.HTTPException) as e:
                raise FetchError("%s while reading %s: %s" % (type(e).__name__, host, e))
            hdrs = {k.lower(): v for k, v in resp.getheaders()}    # servers vary header case
            return Response(current, status, hdrs, body, ctype, charset, hops, truncated)
        finally:
            try:
                conn.close()
            except OSError:
                pass
    raise Blocked("too many redirects (>%d)" % policy.max_redirects)


def _make_conn(scheme, host, port, family, sockaddr, policy, deadline):
    timeout = min(policy.connect_timeout_s, max(0.1, deadline - time.monotonic()))
    if scheme == "https":
        return _PinnedHTTPSConnection(host, port, family, sockaddr, timeout, _tls_context())
    return _PinnedHTTPConnection(host, port, family, sockaddr, timeout)


def _split_content_type(raw):
    ctype, _, rest = raw.partition(";")
    charset = None
    for param in rest.split(";"):
        k, _, v = param.strip().partition("=")
        if k.lower() == "charset":
            charset = v.strip().strip('"')[:40] or None
    return ctype.strip().lower(), charset


def _read_capped(resp, conn, policy, deadline):
    """Read at most policy.max_bytes of DECODED body, under the shared deadline.

    read1(), NOT read(): resp.read(n) loops on the socket until it has n bytes, so a server
    dripping 100 bytes every 0.3s never trips the per-recv timeout and never returns to the
    deadline check - measured: a 3s budget took 196s. read1() returns after one recv, so the
    deadline is re-checked at every trickle. (This is the slowloris fix, verified in tests.)

    Both caps matter: the compressed stream is capped (raw_cap) so a slow/huge transfer cannot
    burn the whole budget, and the decompressed output is capped via decompressobj(max_length)
    so a gzip bomb cannot blow up memory behind a small Content-Length.
    """
    enc = (resp.getheader("Content-Encoding") or "").lower().strip()
    dec = None
    if enc in ("gzip", "x-gzip"):
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif enc == "deflate":
        dec = zlib.decompressobj()
    elif enc not in ("", "identity"):
        raise Blocked("content-encoding %r is not supported" % enc)

    out = bytearray()
    raw_read = 0
    raw_cap = policy.max_bytes * 8 if dec else policy.max_bytes + 65536
    truncated = False
    while len(out) <= policy.max_bytes:
        left = deadline - time.monotonic()
        if left <= 0:
            truncated = True
            break
        try:
            conn.sock.settimeout(min(policy.read_timeout_s, left))
        except (AttributeError, OSError):
            pass
        try:
            chunk = resp.read1(65536)
        except (socket.timeout, TimeoutError):
            truncated = True
            break
        if not chunk:
            break
        raw_read += len(chunk)
        if dec is None:
            out += chunk
        else:
            room = policy.max_bytes + 1 - len(out)
            out += dec.decompress(chunk, room)
            while dec.unconsumed_tail and len(out) <= policy.max_bytes:
                room = policy.max_bytes + 1 - len(out)
                out += dec.decompress(dec.unconsumed_tail, room)
        if raw_read > raw_cap:
            truncated = True
            break
    if len(out) > policy.max_bytes:
        del out[policy.max_bytes:]
        truncated = True
    return bytes(out), truncated
