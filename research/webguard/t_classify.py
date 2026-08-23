import netguard as N
fails=0
DENY=["127.0.0.1","127.1.2.3","10.1.2.3","172.16.0.1","172.31.255.255","192.168.0.1","169.254.169.254",
 "100.100.100.200","100.64.0.1","0.0.0.0","0.1.2.3","255.255.255.255","224.0.0.1","239.1.1.1","240.0.0.1",
 "192.0.0.192","198.18.0.1","192.0.2.1","203.0.113.9","192.88.99.1",
 "::1","::","fe80::1","fec0::1","fc00::1","fd00:ec2::254","ff02::1","2001:db8::1",
 "::ffff:169.254.169.254","::ffff:127.0.0.1","::ffff:10.0.0.1","::a9fe:a9fe","::127.0.0.1",
 "64:ff9b::a9fe:a9fe","64:ff9b::7f00:1","64:ff9b:1::a9fe:a9fe","2002:a9fe:a9fe::1","2002:7f00:1::1",
 "2001:0000:4136:e378:8000:63bf:3fff:fdd2","fe80::1%eth0","not-an-ip","",
 "3fff::1"]
ALLOW=["8.8.8.8","1.1.1.1","93.184.216.34","2606:4700:4700::1111","2a00:1450:4001:80f::200e","2002:0808:0808::1"]
for ip in DENY:
    v=N.classify_ip(ip)
    if v=="ok": print("FAIL should-deny:",ip,v); fails+=1
for ip in ALLOW:
    v=N.classify_ip(ip)
    if v!="ok": print("FAIL should-allow:",ip,v); fails+=1
print("classify: %d vectors, %d failures"%(len(DENY)+len(ALLOW),fails))

P=N.Policy(allow_hosts=("example.com",),allow_subdomains_of=("wikipedia.org",))
BAD=["file:///etc/passwd","ftp://example.com/x","gopher://example.com/","javascript:alert(1)",
 "data:text/html,hi","http://example.com/","https://user:pw@example.com/","https://example.com:22/",
 "https://evil.com/","https://example.com.evil.com/","https://169.254.169.254/","https://[::1]/",
 "https://wikipedia.org.attacker.net/","//example.com/x","https://exa\nmple.com/","https://en.wikipedia.org:8080/",
 "https://EXAMPLE.COM@evil.com/"]
for u in BAD:
    try:
        r=N.validate_url(u,P); print("FAIL should-block:",u,r); fails+=1
    except N.Blocked: pass
GOOD={"https://example.com/":("https","example.com",443,"/"),
      "https://EXAMPLE.com/A?b=c":("https","example.com",443,"/A?b=c"),
      "https://example.com.:443/x":("https","example.com",443,"/x"),
      "https://en.wikipedia.org/wiki/Cat":("https","en.wikipedia.org",443,"/wiki/Cat"),
      "https://wikipedia.org/":("https","wikipedia.org",443,"/")}
for u,exp in GOOD.items():
    try:
        got=N.validate_url(u,P)
        if got!=exp: print("FAIL parse:",u,got,"!=",exp); fails+=1
    except N.Blocked as e: print("FAIL should-allow:",u,e); fails+=1
# IDN
P2=N.Policy(allow_hosts=("xn--bcher-kva.example",))
try:
    print("idn ->",N.validate_url("https://bücher.example/","" or P2))
except Exception as e: print("idn:",type(e).__name__,e)
print("TOTAL FAILURES:",fails)
