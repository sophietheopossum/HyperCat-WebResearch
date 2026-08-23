import html, json, re, sys, unicodedata, urllib.request
from fence import defang_block, ALL_PREFIXES
from frame import render, now_utc

UA = "Mozilla/5.0 (X11; Linux x86_64) HyperCat-WebResearch/0.1"

def get(url, accept="text/html,*/*"):
    r = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept,
                                             "Accept-Language": "en"})
    with urllib.request.urlopen(r, timeout=20) as f:
        raw = f.read(2_000_000)
        return f.status, f.geturl(), f.headers.get("Content-Type",""), raw

def strip_html(b, enc="utf-8"):
    t = b.decode(enc, "replace")
    t = re.sub(r"(?is)<(script|style|noscript|template)\b.*?</\1>", " ", t)
    t = re.sub(r"(?is)<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", t)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = html.unescape(t)
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n\s*\n\s*\n+", "\n\n", t)
    return t.strip()

docs = []
for url in ["https://en.wikipedia.org/api/rest_v1/page/summary/Prompt_injection",
            "https://doc.rust-lang.org/std/string/struct.String.html"]:
    try:
        st, fin, ct, raw = get(url)
    except Exception as e:
        print("FETCH FAIL", url, type(e).__name__, e); continue
    if "json" in ct:
        j = json.loads(raw.decode("utf-8"))
        text = "%s\n\n%s" % (j.get("title",""), j.get("extract",""))
    else:
        text = strip_html(raw)
    print("OK %s -> %s %s ct=%s raw=%dB text=%dB" % (url, st, fin, ct.split(";")[0], len(raw), len(text.encode())))
    print("   first 180 chars of extracted text: %r" % text[:180])
    docs.append({"url": url, "final_url": fin,
                 "http": "%s %s · %d B extracted · retrieved %s" % (st, ct.split(";")[0], len(text.encode()), now_utc()),
                 "text": text})

if not docs:
    sys.exit("no docs fetched")

# What does defang actually change on REAL content?
for d in docs:
    before = d["text"]
    after = defang_block(before)
    removed = [ (hex(ord(c)), unicodedata.category(c)) for c in before if c not in after and unicodedata.category(c) in ("Cc","Cf","Cs","Co","Cn") ]
    print("\n%s: %d chars in, %d out, delta %d" % (d["url"].split("/")[2], len(before), len(after), len(before)-len(after)))
    cats = {}
    for c in before:
        cat = unicodedata.category(c)
        if cat in ("Cc","Cf","Cs","Co","Cn") and c not in "\n\t":
            cats[(hex(ord(c)), cat)] = cats.get((hex(ord(c)), cat), 0) + 1
    print("   control/format codepoints stripped:", cats or "none")
    # word-level fidelity check
    import difflib
    w1, w2 = before.split(), after.split()
    print("   words in/out: %d / %d  identical=%s" % (len(w1), len(w2), w1 == w2))

n = "a1b2c3d4"
out = render(n, docs)
print("\n--- RENDERED (%d bytes) ---" % len(out.encode()))
print(out[:1400])
print("   ...")
print(out[-260:])
assert out.endswith("[end web content %s]" % n)
print("\nclose marker intact:", out.endswith("[end web content %s]" % n))
