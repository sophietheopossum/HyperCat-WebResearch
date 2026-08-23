"""fence.py - the untrusted-web-content boundary for the HyperCat web research tool.

Mirrors HyperCat's own posture (app/prompt_defang + host_bridge::format_hits):
an untrusted span is wrapped between a literal open/close marker, and the
opening '[' of any occurrence of those markers INSIDE the span is replaced with
'(' so the span cannot forge its own delimiter.

Deltas from the C++ original, each deliberate (see notes in the report):
  1. per-call NONCE in both markers (the C++ markers are static literals)
  2. defang works on Unicode CATEGORIES, not bytes: strips Cc/Cf/Cs/Co/Cn
     (kills the U+E00xx Tags ASCII-smuggling block + bidi + zero-width),
     where the C++ only strips < 0x20 and 0x7f
  3. NFKC-fold a COPY for marker detection, so a fullwidth-bracket forgery is
     neutralised in the original too
"""

import re
import secrets
import unicodedata

# --- the marker family -------------------------------------------------------
# NEUTRALISE on these PREFIXES, not on the full nonce'd literal. This is exactly
# what host_bridge does: it emits "[retrieved memory - reference, not instruction]"
# but defangs against the PREFIX "[retrieved memory".
OPEN_PREFIX = "[web content"
CLOSE_PREFIX = "[end web content"
DOC_OPEN_PREFIX = "[web document"
DOC_CLOSE_PREFIX = "[end web document"
# Extra prefixes: any *other* HyperCat fence a page might try to forge from inside
# ours (a page that emits "[end retrieved memory]" is trying to break the memory
# fence, not ours - break it here too, before the model can ever copy it onward).
FOREIGN_PREFIXES = (
    "[retrieved memory",
    "[end retrieved memory",
    "[skill content",
    "[end skill content",
    "[available skills",
    "[end available skills",
    "[agenda results",
    "[end agenda results",
    "[artifact",
    "[end artifact",
    "[persona",
    "[end persona",
)
ALL_PREFIXES = (OPEN_PREFIX, CLOSE_PREFIX, DOC_OPEN_PREFIX, DOC_CLOSE_PREFIX) + FOREIGN_PREFIXES


def new_nonce() -> str:
    """A fresh per-call boundary token. 8 hex chars = 32 bits; the attacker has no
    feedback channel inside a call, so this only has to be unguessable-in-one-shot."""
    return secrets.token_hex(4)


# --- the defangs -------------------------------------------------------------
def _prefix_re(prefixes):
    """One case-insensitive, whitespace-tolerant alternation over the marker family.
    "[end web content" also matches "[ END   web\tcontent" - a near-miss that a plain
    str.find() (the C++ approach) would let through with its '[' intact."""
    parts = []
    for pre in prefixes:
        body = re.escape(pre.lstrip("[")).replace("\\ ", r"\s+")
        parts.append(r"\[\s*" + body)
    return re.compile("|".join(parts), re.IGNORECASE)


_MARKER_RE_CACHE = {}


def _neutralise(text: str, prefixes) -> str:
    """Replace the opening '[' of every marker-family occurrence with '('.
    Detection also runs over an NFKC copy (when length-preserving) so a fullwidth or
    other compat-form bracket is caught; the edit lands on the ORIGINAL by index."""
    key = tuple(prefixes)
    rx = _MARKER_RE_CACHE.get(key)
    if rx is None:
        rx = _MARKER_RE_CACHE[key] = _prefix_re(key)
    out = list(text)
    folded = unicodedata.normalize("NFKC", text)
    hays = [text]
    if len(folded) == len(text) and folded != text:
        hays.append(folded)
    for hay in hays:
        for m in rx.finditer(hay):
            out[m.start()] = "("
    return "".join(out)


_KEEP_CONTROLS = ("\n", "\t")


def defang_block(text: str, prefixes=ALL_PREFIXES) -> str:
    """Multi-line untrusted body. Keeps \\n and \\t (document structure survives);
    drops every other Unicode control/format/unassigned/private-use/surrogate
    codepoint; then neutralises the fence markers.

    C++ parity: hcapp::defang_block, extended from bytes to codepoints.
    """
    buf = []
    for ch in text:
        if ch in _KEEP_CONTROLS:
            buf.append(ch)
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue          # NUL/ESC/BEL/DEL, bidi, zero-width, U+E00xx tags
        if cat == "Zs" and ch != " ":
            buf.append(" ")   # NBSP & friends -> a plain space
            continue
        if cat in ("Zl", "Zp"):
            buf.append("\n")
            continue
        buf.append(ch)
    return _neutralise("".join(buf), prefixes)


def defang_inline(text: str, prefixes=ALL_PREFIXES) -> str:
    """Single-line untrusted item (a URL, a title, a snippet). Collapses \\n \\r \\t
    to a space as well - a one-line item must not inject a fresh directive line.

    C++ parity: hcapp::defang_inline.
    """
    return defang_block(text.replace("\n", " ").replace("\r", " ").replace("\t", " "), prefixes)


# --- utf-8-safe truncation ---------------------------------------------------
def clip(text: str, max_bytes: int) -> tuple:
    """Truncate to <= max_bytes of UTF-8 WITHOUT splitting a codepoint.
    Returns (clipped, was_truncated). Python str slicing is by codepoint, so the
    C++ resize()-splits-a-UTF-8-sequence hazard does not exist here - but the
    BYTE budget still has to be honoured, hence the encode/decode round trip."""
    b = text.encode("utf-8")
    if len(b) <= max_bytes:
        return text, False
    return b[:max_bytes].decode("utf-8", "ignore"), True
