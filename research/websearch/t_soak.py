import sys, time; sys.path.insert(0,'.')
import backends
QS=("kwin effects,gnome mutter,sway config,hyprland plugin,river layout,niri scroll,labwc theme,"
    "weston ivi,wlroots scene,cage kiosk,greetd config,seatd libseat,pam mount,polkit rules,"
    "udev rule syntax,systemd socket activation,dbus interface,gsettings schema,xdg desktop portal,"
    "flatpak override").split(",")
for gap in (2, 0):
    ok=0; blocked=0
    print("--- gap=%ds, %d queries ---"%(gap,len(QS)),flush=True)
    for q in QS:
        try:
            rs=backends.ddg_html(q,n=10); ok+=1
        except backends.Blocked as e:
            blocked+=1; print("   BLOCKED %-24s %s"%(q,e),flush=True)
        except Exception as e:
            print("   ERR %-24s %s"%(q,e),flush=True)
        time.sleep(gap)
    print("== gap=%ds ok=%d blocked=%d\n"%(gap,ok,blocked),flush=True)
    time.sleep(20)
