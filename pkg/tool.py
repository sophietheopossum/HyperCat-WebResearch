#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""webresearch — keyless web search and single-page fetch for a HyperCat agent.

WHAT THIS IS FOR. A HyperCat agent has no way to look anything up: there is no web tool in the
built-in roster, `run` is deny-all without an exec allowlist, and egress is default-denied. Research
therefore meant a human fetching pages by hand. This closes that, narrowly.

THE SHAPE OF THE RISK. This hands an agent attacker-authored text, and that agent has a PERSISTENT
memory store it can write to. Prompt injection into persistence is the hazard that matters: a page
that talks the agent into remembering something survives the session. Nothing here can prevent that
outright. What it does is (a) make every returned document unambiguously DATA -- fenced, with the
delimiter defanged so page text cannot forge the end of the block -- and (b) keep the blast radius
small: fetch-only, no credentials, https-only, size- and time-capped, and never a private address.

WHY THE GUARD IS IN-PROCESS. The manifest's `egress_hosts` is DECLARED INTENT in tool ABI v1, not a
firewall: a non-empty list grants unrestricted egress at the kernel floor and drives the operator's
review. Per-host enforcement does not exist. So netguard.py is the only thing actually deciding where
this tool may connect, and the escape it exists to close is REDIRECTS -- a permitted host answering
302 to somewhere else. Every hop is re-validated against the resolved IP, not the hostname.
"""
import backends
import defang
import netguard

import hypercat_tool

# Search reaches only these, and they are OUR urls, never the model's -- so a name allowlist is
# meaningful here in a way it is not for web_fetch. Keep in step with manifest egress_hosts.
_SEARCH_POLICY = netguard.Policy(
    allow_hosts=("html.duckduckgo.com", "api.marginalia.nu", "api.mwmbl.org"),
    allowed_ports=(443,), max_redirects=2, max_bytes=2 * 1024 * 1024, total_timeout_s=12.0,
    user_agent=backends.UA,   # DuckDuckGo serves an anomaly page to a non-browser UA
)
# Install it. This line is what makes the policy above real -- it was defined and never applied
# once, and search consequently ran on bare urllib with no redirect re-validation at all.
backends.use_policy(_SEARCH_POLICY)

# web_fetch takes a URL FROM THE MODEL, so no name allowlist can apply. The protections are the
# IP classification (private/loopback/link-local/cloud-metadata all refused), https-only, one port,
# a bounded redirect chain re-checked at every hop, and hard size/time caps.
_FETCH_POLICY = netguard.Policy(
    allow_any_host=True, allow_plain_http=False, allow_ip_literals=False,
    allowed_ports=(443,), max_redirects=5, max_bytes=2 * 1024 * 1024,
    total_timeout_s=20.0, connect_timeout_s=6.0, read_timeout_s=8.0,
)


def _extract_text(html_bytes, charset):
    """HTML -> readable text, stdlib only. Deliberately simple: drop script/style/head, unwrap tags,
    collapse whitespace. It produces navigation soup on a heavy page, which is why the fence header
    says so -- an agent told the extraction is crude will treat a thin result as thin, whereas one
    given confident-looking mush will summarise the mush."""
    import html as _html
    import re

    txt = html_bytes.decode(charset or "utf-8", "replace")
    txt = re.sub(r"(?is)<(script|style|head|noscript)[^>]*>.*?</\1>", " ", txt)
    txt = re.sub(r"(?is)<br\s*/?>|</(p|div|li|tr|h[1-6])>", "\n", txt)
    txt = re.sub(r"(?s)<[^>]+>", " ", txt)
    txt = _html.unescape(txt)
    txt = re.sub(r"[ \t\r\f\v]+", " ", txt)
    txt = re.sub(r"\n\s*\n\s*\n+", "\n\n", txt)
    return "\n".join(line.strip() for line in txt.split("\n")).strip()


def web_search(args):
    q = (args.get("query") or "").strip()
    if not q:
        raise ValueError("query is required")
    n = args.get("max_results") or 5
    try:
        n = max(1, min(10, int(n)))
    except (TypeError, ValueError):
        n = 5

    # DuckDuckGo first: the only keyless option with real coverage. It blocks with HTTP *202* and an
    # anomaly page, so backends detects a block by the RESULT MARKER, never the status code. On a
    # block it falls straight through -- there is no retry, here or in the backend -- because
    # Marginalia and Mwmbl fail independently (they stall or return empty; they do not IP-block),
    # so the chain is not three rolls of the same die. Retrying DDG harder only extends the block.
    errs = []
    for name, fn in (("duckduckgo", backends.ddg_html),
                     ("marginalia", backends.marginalia),
                     ("mwmbl", backends.mwmbl)):
        try:
            results = fn(q, n=n)
        except Exception as e:                      # noqa: BLE001 - any backend failure falls through
            errs.append("%s: %s" % (name, str(e)[:120]))
            continue
        if results:
            return defang.format_results(q, name, results)
    raise RuntimeError("no search backend returned results (%s)" % "; ".join(errs))


def web_fetch(args):
    url = (args.get("url") or "").strip()
    if not url:
        raise ValueError("url is required")
    cap = args.get("max_chars") or 8000
    try:
        cap = max(500, min(40000, int(cap)))
    except (TypeError, ValueError):
        cap = 8000

    r = netguard.fetch(url, _FETCH_POLICY)          # raises Blocked / FetchError with a reason
    text = _extract_text(r.body, getattr(r, "charset", None))
    truncated = len(text) > cap
    if truncated:
        text = text[:cap]

    # The hop list matters and is not decoration: the operator gate fires BEFORE the fetch, so if a
    # permitted URL redirected somewhere else, this record is the only place that is visible after
    # the fact. Both the URL and the page text are attacker-controlled and are defanged.
    hops = getattr(r, "hops", None) or [url]
    header = ("source: %s\nfinal : %s\nhops  : %d\nhttp  : %s %s · %d chars extracted%s\n"
              "note  : extraction is a plain tag-strip; a heavy page yields navigation text too"
              % (defang.defang_inline(url), defang.defang_inline(hops[-1]), len(hops),
                 getattr(r, "status", "?"), defang.defang_inline(getattr(r, "content_type", "?") or "?"),
                 len(text), " · TRUNCATED" if truncated else ""))
    return "%s\n%s\n\n%s\n%s" % (defang.PAGE_OPEN, header, defang.defang_web(text), defang.PAGE_CLOSE)


if __name__ == "__main__":
    raise SystemExit(hypercat_tool.serve({"web_search": web_search, "web_fetch": web_fetch}))
