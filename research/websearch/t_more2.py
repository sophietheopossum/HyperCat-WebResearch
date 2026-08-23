import re
from probe import *
Q="landlock seccomp sandbox"; qq=urllib.parse.quote(Q)
UA_TOOL="HyperCatWebSearch/0.1"
BROWSER = {"User-Agent": UA_REAL,
  "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language":"en-GB,en;q=0.5"}
tests = [
 ("mwmbl",      "https://api.mwmbl.org/api/v1/search/?s="+qq, None, {"User-Agent":UA_TOOL}),
 ("qwant",      "https://api.qwant.com/v3/search/web?q=%s&count=10&locale=en_GB&offset=0&device=desktop&tgp=3&safesearch=1"%qq, None, dict(BROWSER, Origin="https://www.qwant.com", Referer="https://www.qwant.com/")),
 ("stract-web", "https://stract.com/search?q="+qq, None, BROWSER),
 ("stract-api2","https://stract.com/beta/api/search", json.dumps({"query":Q}).encode(), {"User-Agent":UA_REAL,"Content-Type":"application/json","Accept":"application/json"}),
 ("rightdao",   "https://rightdao.com/search?query="+qq, None, BROWSER),
 ("wikipedia-ua","https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=%s&srlimit=5&format=json&formatversion=2"%urllib.parse.quote("linux kernel"), None, {"User-Agent":UA_TOOL}),
 ("openalex",   "https://api.openalex.org/works?search=%s&per-page=5"%qq, None, {"User-Agent":UA_TOOL}),
 ("crossref",   "https://api.crossref.org/works?query=%s&rows=5"%qq, None, {"User-Agent":UA_TOOL}),
 ("arxiv",      "http://export.arxiv.org/api/query?search_query=all:%s&max_results=5"%urllib.parse.quote("seccomp sandbox"), None, {"User-Agent":UA_TOOL}),
 ("github-code","https://api.github.com/search/repositories?q=%s&per_page=5"%qq, None, {"User-Agent":UA_TOOL,"Accept":"application/vnd.github+json"}),
]
for tag,url,data,hdr in tests:
    r=fetch(url,data=data,headers=hdr,timeout=20)
    show(tag,r,280)
    if "body" in r: open("out_%s.bin"%tag,"wb").write(r["body"])
    time.sleep(1)
