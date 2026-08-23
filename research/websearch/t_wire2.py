import socket, threading, time, sys; sys.path.insert(0,'.')
import backends
CAP=[]
def srv(port):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",port)); s.listen(5)
    for _ in range(2):
        c,_a=s.accept(); c.settimeout(2); buf=b""
        try:
            while b"\r\n\r\n" not in buf:
                d=c.recv(4096)
                if not d: break
                buf+=d
        except Exception: pass
        CAP.append(buf.decode("latin1"))
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); c.close()
    s.close()
t=threading.Thread(target=srv,args=(8732,),daemon=True); t.start(); time.sleep(0.3)
backends._get("http://127.0.0.1:8732/a")
backends._get("http://127.0.0.1:8732/b", headers={"Accept":"application/json"})
t.join(5)
for i,c in enumerate(CAP): print("---- %d ----"%i); print(c)
