import sys, time, datetime; sys.path.insert(0,'.')
import backends
GAP=int(sys.argv[1]); QS=sys.argv[2:]
for i,q in enumerate(QS):
    t=datetime.datetime.now().strftime("%H:%M:%S")
    try:
        rs=backends.ddg_html(q, n=10)
        print("%s #%d gap=%ds %-22s OK n=%d" % (t,i,GAP,q[:22],len(rs)), flush=True)
    except Exception as e:
        print("%s #%d gap=%ds %-22s %s: %s" % (t,i,GAP,q[:22],type(e).__name__,e), flush=True)
    time.sleep(GAP)
