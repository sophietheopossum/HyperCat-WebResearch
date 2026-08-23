import socket, threading, urllib.request, time
CAP=[]
def srv(port):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",port)); s.listen(5)
    for _ in range(3):
        c,_a=s.accept(); c.settimeout(2)
        buf=b""
        try:
            while b"\r\n\r\n" not in buf: 
                d=c.recv(4096)
                if not d: break
                buf+=d
        except Exception: pass
        CAP.append(buf.decode("latin1"))
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); c.close()
    s.close()
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
ACC="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
t=threading.Thread(target=srv,args=(8731,),daemon=True); t.start(); time.sleep(0.3)
def go(pairs):
    r=urllib.request.Request("http://127.0.0.1:8731/x")
    for k,v in pairs: r.add_header(k,v)
    urllib.request.urlopen(r,timeout=3).read()
go([("User-Agent",UA),("Accept",ACC),("Accept-Language","en-GB,en;q=0.5"),("Accept-Encoding","gzip, deflate")])
go([("Accept",ACC),("Accept-Language","en-GB,en;q=0.5"),("Accept-Encoding","gzip, deflate"),("User-Agent",UA)])
go([("User-Agent",UA)])
t.join(5)
for i,c in enumerate(CAP):
    print("---- capture %d ----"%i); print(c)
