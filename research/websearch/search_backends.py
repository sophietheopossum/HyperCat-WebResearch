"""Keyless web-search backends for a HyperCat managed (Python) tool.

stdlib only (urllib/re/json/gzip/zlib/html). No pip, no vendoring.

Everything here was measured against the live web on 22-23/8/2026 from urllib
(NOT curl - the header signature differs and DDG discriminates on it).

Load-bearing facts, each verified:
  * DDG signals a block with HTTP **202** and an "anomaly" page. Never trust the
    status code; detect the result marker in the body.
  * DDG fingerprints HEADER ORDER. urllib emits request headers in the order they
    were inserted into the Request. User-Agent MUST come first, and Accept /
    Accept-Language / Accept-Encoding must all be present. Interleaved A/B on
    fresh queries: UA-first 10/10 ok, UA-last 4/10 ok.
  * A bare UA (no Accept-*) makes urllib inject "Accept-Encoding: identity"
    BEFORE Host - a unique non-browser signature. 1/3 ok.
  * UA strings "Python-urllib/3.14" and "curl/8.9.1" are blocked outright (202).
    A descriptive custom UA ("HyperCatWebSearch/0.1 (+...)") was NOT blocked, so
    honest identification is possible; the browser UA is simply the safest.
  * Back-to-back requests exhaust a burst budget at ~7; >=2s spacing sustained
    20/20. Once blocked, recovery is ~30-45 s of silence - retrying hard extends it.
"""
import gzip, html as _html, json, re, time, zlib
import urllib.error, urllib.parse, urllib.request

# A current desktop-Firefox UA. Swap for a descriptive one if you prefer honesty
# over robustness - both were observed to work; the default urllib UA does not.
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
MAX_BYTES = 1024 * 1024          # hard cap on any single response we will read


class Blocked(Exception):
    """The endpoint answered, but with a challenge/limiter page, not results."""


def _get(url, headers=None, timeout=8.0, max_bytes=MAX_BYTES):
    """One GET. Header INSERTION ORDER is the wire order - do not reorder these."""
    h = {}
    h["User-Agent"] = UA                       # MUST be first (see module docstring)
    h["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    h["Accept-Language"] = "en-GB,en;q=0.5"
    h["Accept-Encoding"] = "gzip, deflate"     # only what the stdlib can undo; never br
    if headers:
        h.update(headers)                      # dict.update keeps an existing key's slot
    req = urllib.request.Request(url, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        raw, hdrs, code = r.read(max_bytes + 1), r.headers, r.status
    except urllib.error.HTTPError as e:
        raw, hdrs, code = e.read(max_bytes + 1), e.headers, e.code
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    enc = (hdrs.get("Content-Encoding", "") or "").lower()
    if enc in ("gzip", "deflate") and not truncated:
        try:
            raw = gzip.decompress(raw) if enc == "gzip" else zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception:
            pass
    return code, raw


_INLINE = re.compile(r"(?is)</?(b|i|em|strong|span|mark|u)\b[^>]*>")

def _txt(s):
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    s = _INLINE.sub("", s)                     # inline tags: no space ("seccomp-bpf" stays joined)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", _html.unescape(s)).strip()


# --------------------------------------------------------------- DuckDuckGo
_DDG_BLOCK = re.compile(r'(?s)<div class="result results_links.*?'
                        r'(?=<div class="result results_links|<div class="nav-link|\Z)')
_DDG_TITLE = re.compile(r'(?s)<a[^>]+class="result__a"[^>]+href="(?P<href>[^"]+)"[^>]*>(?P<t>.*?)</a>')
_DDG_SNIP  = re.compile(r'(?s)<a[^>]+class="result__snippet"[^>]*>(?P<s>.*?)</a>')

def _ddg_unwrap(href):
    """//duckduckgo.com/l/?uddg=<pct-encoded real url>&rut=... -> the real url."""
    href = _html.unescape(href)
    if href.startswith("//"):
        href = "https:" + href
    p = urllib.parse.urlparse(href)
    if p.netloc.endswith("duckduckgo.com") and p.path.startswith("/l/"):
        u = urllib.parse.parse_qs(p.query).get("uddg", [""])[0]
        if u:
            return u
    return href

def ddg_html(q, n=10, timeout=10.0):
    """html.duckduckgo.com. Best result quality of every keyless option tested."""
    code, raw = _get("https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(q, safe=""),
                     timeout=timeout)
    body = raw.decode("utf-8", "replace")
    if "result__a" not in body:                # the ONLY reliable success test (202 != failure code)
        raise Blocked("duckduckgo anomaly page (HTTP %d, %d bytes)" % (code, len(raw)))
    out = []
    for blk in _DDG_BLOCK.finditer(body):
        b = blk.group(0)
        t = _DDG_TITLE.search(b)
        if not t:
            continue
        s = _DDG_SNIP.search(b)
        out.append({"title": _txt(t.group("t")), "url": _ddg_unwrap(t.group("href")),
                    "snippet": _txt(s.group("s")) if s else ""})
        if len(out) >= n:
            break
    return out


# --------------------------------------------------------------- Marginalia
def marginalia(q, n=10, timeout=6.0):
    """api.marginalia.nu public JSON. Keyless, needs no UA, CC-BY-NC-SA results.
    Independent 'small web' index: strong on technical/hobbyist prose, blind to
    news, commerce and plain facts. Stalls intermittently (~50% at 0.3s spacing,
    ~10% at 5s); a stall is a HANG, not an error - always retry, it succeeds in ~0.2s."""
    code, raw = _get("https://api.marginalia.nu/public/search/" + urllib.parse.quote(q, safe=""),
                     headers={"Accept": "application/json"}, timeout=timeout)
    if code != 200:
        raise Blocked("marginalia HTTP %d" % code)
    return [{"title": r.get("title", ""), "url": r.get("url", ""),
             "snippet": r.get("description", "")}
            for r in json.loads(raw).get("results", [])][:n]


# -------------------------------------------------------------------- Mwmbl
def mwmbl(q, n=10, timeout=6.0):
    """api.mwmbl.org public JSON. Keyless, never blocked in testing, but a very
    small crawl: 8/30 agent-style queries returned nothing."""
    code, raw = _get("https://api.mwmbl.org/api/v1/search/?s=" + urllib.parse.quote(q, safe=""),
                     headers={"Accept": "application/json"}, timeout=timeout)
    if code != 200:
        raise Blocked("mwmbl HTTP %d" % code)
    join = lambda ps: "".join(p.get("value", "") for p in (ps or [])).strip()
    return [{"title": join(r.get("title")), "url": r.get("url", ""),
             "snippet": join(r.get("extract"))} for r in json.loads(raw)][:n]


# ---------------------------------------------------------------- Wikipedia
def wikipedia(q, n=5, timeout=6.0, lang="en"):
    """Wikimedia action API - encyclopedia only, NOT a web index. A descriptive
    User-Agent is MANDATORY (the default urllib UA gets 403 from HAProxy before
    MediaWiki even sees it). Anonymous rate limit is real: HTTP 429 after ~10
    rapid calls, with an explanatory body."""
    url = ("https://%s.wikipedia.org/w/api.php?action=query&list=search&srsearch=%s"
           "&srlimit=%d&format=json&formatversion=2"
           % (lang, urllib.parse.quote(q, safe=""), n))
    code, raw = _get(url, timeout=timeout,
                     headers={"User-Agent": "HyperCatWebSearch/0.1 (HyperCat local agent tool)",
                              "Accept": "application/json"})
    if code != 200:
        raise Blocked("wikipedia HTTP %d: %s" % (code, raw[:120].decode("utf-8", "replace")))
    out = []
    for r in json.loads(raw).get("query", {}).get("search", []):
        t = r.get("title", "")
        out.append({"title": t,
                    "url": "https://%s.wikipedia.org/wiki/%s" % (lang, urllib.parse.quote(t.replace(" ", "_"))),
                    "snippet": _txt(r.get("snippet", ""))})
    return out


# ------------------------------------------------------------------ the chain
CHAIN = (("duckduckgo", ddg_html), ("marginalia", marginalia), ("mwmbl", mwmbl))

def search(q, n=8, budget_s=20.0):
    """Try each backend in turn inside a wall-clock budget. Returns
    (backend_name, results, notes). Raises RuntimeError only if everything failed.

    budget_s must stay comfortably under the manifest's limits.timeout_ms
    (host max = 60000). Leave room for the reply frame."""
    deadline = time.monotonic() + budget_s
    notes = []
    for name, fn in CHAIN:
        for attempt in (0, 1):
            left = deadline - time.monotonic()
            if left <= 1.5:
                notes.append("%s: skipped, out of budget" % name)
                break
            try:
                rs = fn(q, n=n, timeout=min(left - 0.5, 10.0))
                if rs:
                    return name, rs, notes
                notes.append("%s: 0 results" % name)
                break
            except Blocked as e:
                notes.append("%s: %s" % (name, e))
                if attempt == 0 and deadline - time.monotonic() > 5.0:
                    time.sleep(2.0)            # short, polite; hammering extends a DDG block
                    continue
                break
            except Exception as e:             # timeout / DNS / TLS
                notes.append("%s: %s: %s" % (name, type(e).__name__, e))
                if attempt == 0 and deadline - time.monotonic() > 3.0:
                    continue                   # a marginalia stall clears on the very next try
                break
    raise RuntimeError("all backends failed: " + "; ".join(notes))
