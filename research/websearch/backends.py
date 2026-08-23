"""Tested keyless search backends. stdlib only; urllib only. Each returns [{title,url,snippet}]."""
import gzip, html as _html, json, re, socket, ssl, time, zlib
import urllib.error, urllib.parse, urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
MAX_BYTES = 2 * 1024 * 1024


class Blocked(Exception):
    """The endpoint answered, but with a challenge/limiter page instead of results."""


def _get(url, data=None, headers=None, timeout=8.0, max_bytes=MAX_BYTES):
    h = {"User-Agent": UA,
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Language": "en-GB,en;q=0.5",
         "Accept-Encoding": "gzip, deflate"}
    if headers:
        h.update(headers)
    if isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        raw, hdrs, code = r.read(max_bytes + 1), r.headers, r.status
    except urllib.error.HTTPError as e:
        raw, hdrs, code = e.read(max_bytes + 1), e.headers, e.code
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    enc = (hdrs.get("Content-Encoding", "") or "").lower()
    if enc == "gzip":
        try: raw = gzip.decompress(raw)
        except Exception: pass
    elif enc == "deflate":
        try: raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception: pass
    return code, raw


def _txt(s):
    """Strip tags, unescape entities, collapse whitespace."""
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    s = re.sub(r"(?is)</?(b|i|em|strong|span|mark|u)\b[^>]*>", "", s)  # inline: no space, or "seccomp-bpf" -> "seccomp -bpf"
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", _html.unescape(s)).strip()


# ---------------------------------------------------------------- marginalia
def marginalia(q, n=10, timeout=8.0):
    """api.marginalia.nu public JSON. Keyless, no UA needed. Independent 'small web' index."""
    url = "https://api.marginalia.nu/public/search/" + urllib.parse.quote(q, safe="")
    code, raw = _get(url, timeout=timeout, headers={"Accept": "application/json"})
    if code != 200:
        raise Blocked("marginalia HTTP %d" % code)
    d = json.loads(raw)
    return [{"title": r.get("title", ""), "url": r.get("url", ""),
             "snippet": r.get("description", "")} for r in d.get("results", [])][:n]


# --------------------------------------------------------------------- mwmbl
def mwmbl(q, n=10, timeout=8.0):
    """api.mwmbl.org public JSON. Keyless. Small independent crawl; title/extract are token runs."""
    url = "https://api.mwmbl.org/api/v1/search/?s=" + urllib.parse.quote(q, safe="")
    code, raw = _get(url, timeout=timeout, headers={"Accept": "application/json"})
    if code != 200:
        raise Blocked("mwmbl HTTP %d" % code)
    join = lambda parts: "".join(p.get("value", "") for p in (parts or [])).strip()
    return [{"title": join(r.get("title")), "url": r.get("url", ""),
             "snippet": join(r.get("extract"))} for r in json.loads(raw)][:n]


# ---------------------------------------------------------------------- wiby
def wiby(q, n=10, timeout=8.0):
    """wiby.me public JSON. Keyless. Tiny hand-curated 'old web' index; often 0 results."""
    url = "https://wiby.me/json/?q=" + urllib.parse.quote(q, safe="")
    code, raw = _get(url, timeout=timeout, headers={"Accept": "application/json"})
    if code != 200:
        raise Blocked("wiby HTTP %d" % code)
    raw = raw.strip()
    if not raw:
        return []
    return [{"title": _html.unescape(r.get("Title", "")), "url": r.get("URL", ""),
             "snippet": _html.unescape(r.get("Snippet", ""))} for r in json.loads(raw)][:n]


# ------------------------------------------------------------------ ddg html
_DDG_BLOCK = re.compile(r'(?s)<div class="result results_links.*?(?=<div class="result results_links|<div class="nav-link|\\Z)')
_DDG_TITLE = re.compile(r'(?s)<a[^>]+class="result__a"[^>]+href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>')
_DDG_SNIP = re.compile(r'(?s)<a[^>]+class="result__snippet"[^>]*>(?P<s>.*?)</a>')

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
    """html.duckduckgo.com. Best coverage of the keyless options, but IP-blocks aggressively.
    A block is HTTP *202* with an 'anomaly' page - status alone will not tell you."""
    url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(q, safe="")
    code, raw = _get(url, timeout=timeout)
    body = raw.decode("utf-8", "replace")
    if "result__a" not in body:
        raise Blocked("ddg anomaly/challenge page (HTTP %d, %d bytes)" % (code, len(raw)))
    out = []
    for blk in _DDG_BLOCK.finditer(body):
        b = blk.group(0)
        t = _DDG_TITLE.search(b)
        if not t:
            continue
        sn = _DDG_SNIP.search(b)
        out.append({"title": _txt(t.group("title")),
                    "url": _ddg_unwrap(t.group("href")),
                    "snippet": _txt(sn.group("s")) if sn else ""})
        if len(out) >= n:
            break
    return out


# ------------------------------------------------------------ marginalia html
_MARG_CARD = re.compile(r'(?s)<section[^>]+class="card search-result"(?P<body>.*?)</section>')
_MARG_TITLE = re.compile(r'(?s)<a[^>]+class="title"[^>]+href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>')
_MARG_DESC = re.compile(r'(?s)<p class="description">(?P<d>.*?)</p>')

def marginalia_html(q, n=10, timeout=10.0):
    """old-search.marginalia.nu HTML - the fallback if the JSON API stalls (separate host/path)."""
    url = "https://old-search.marginalia.nu/search?query=" + urllib.parse.quote(q, safe="")
    code, raw = _get(url, timeout=timeout)
    body = raw.decode("utf-8", "replace")
    if "card search-result" not in body:
        raise Blocked("marginalia html: no result cards (HTTP %d)" % code)
    out = []
    for card in _MARG_CARD.finditer(body):
        c = card.group("body")
        t = _MARG_TITLE.search(c)
        if not t:
            continue
        d = _MARG_DESC.search(c)
        out.append({"title": _txt(t.group("title")), "url": _html.unescape(t.group("href")),
                    "snippet": _txt(d.group("d")) if d else ""})
        if len(out) >= n:
            break
    return out


# ----------------------------------------------------------------- wikipedia
def wikipedia(q, n=5, timeout=8.0, lang="en"):
    """Wikimedia action API. Encyclopedia-only (NOT a web index). A descriptive User-Agent is
    MANDATORY: the default 'Python-urllib/3.x' UA gets a 403 from HAProxy before MediaWiki."""
    url = ("https://%s.wikipedia.org/w/api.php?action=query&list=search&srsearch=%s"
           "&srlimit=%d&format=json&formatversion=2" % (lang, urllib.parse.quote(q, safe=""), n))
    code, raw = _get(url, timeout=timeout,
                     headers={"User-Agent": "HyperCatWebSearch/0.1 (local agent tool)",
                              "Accept": "application/json"})
    if code != 200:
        raise Blocked("wikipedia HTTP %d: %s" % (code, raw[:120].decode("utf-8", "replace")))
    d = json.loads(raw)
    out = []
    for r in d.get("query", {}).get("search", []):
        out.append({"title": r.get("title", ""),
                    "url": "https://%s.wikipedia.org/wiki/%s" % (lang, urllib.parse.quote(r.get("title", "").replace(" ", "_"))),
                    "snippet": _txt(r.get("snippet", ""))})
    return out


ALL = {"marginalia": marginalia, "mwmbl": mwmbl, "wiby": wiby,
       "ddg_html": ddg_html, "marginalia_html": marginalia_html, "wikipedia": wikipedia}
