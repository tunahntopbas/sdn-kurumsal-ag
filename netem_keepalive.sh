#!/bin/bash
# netem_keepalive.sh
# Apple Silicon Multipass VM uzerinde tc/netem gecikmesini deterministik yapar.
#
# Sorun: Bosta (idle) VM'de vCPU WFI (halt) durumuna girer. macOS hypervisor
# bu durumda sanal timer kesmesini gec iletir; netem'in paket-birakma hrtimer'i
# gec ateslenir ve paketler toplu salinir. Sonuc: WAN link (delay 20ms x2)
# RTT'si beklenen ~40ms yerine 50-240ms arasi dalgalanir, mdev ~30ms.
#
# Kok neden kaniti (izole test: saf veth+netns, Mininet/OVS/POX YOK):
#   bosta          : rtt avg 127ms  mdev 29ms   (kotu)
#   2 vCPU mesgul  : rtt avg 40.05ms mdev 0.018ms (kusursuz)
# idle=poll ise ARM'da cpu_relax=YIELD kullandigi icin ise yaramadi
# (hypervisor YIELD'i deschedule ipucu sayiyor) ve saat geri atlamasina yol acti.
#
# Cozum: her vCPU'yu nice-19 bir spinner ile surekli "sicak" tut. Host vCPU
# thread'ini idle sanip deschedule etmez, sanal timer zamaninda gelir. nice-19
# oldugu icin gercek Mininet/POX/OVS trafigi aninda one gecer; olcumde CPU
# rekabeti yasanmaz.
#
# Kullanim: ./netem_keepalive.sh start | stop | status
# Olcumden once start, bittiginde stop. Spinnerlar her vCPU'yu %100 gosterir
# (laptop fani doner) ama bu sadece "mesgul tutma"dir, gercek is onceliklidir.

PIDFILE="${HOME}/.netem_keepalive.pids"

case "$1" in
  start)
    : > "$PIDFILE"
    N=$(nproc)
    for c in $(seq 0 $((N-1))); do
      setsid nice -n 19 taskset -c "$c" bash -c "while :; do :; done" \
        </dev/null >/dev/null 2>&1 &
      echo $! >> "$PIDFILE"
    done
    echo "keepalive basladi: $N spinner (nice 19), pid: $(tr '\n' ' ' < "$PIDFILE")"
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then kill $(cat "$PIDFILE") 2>/dev/null; fi
    rm -f "$PIDFILE"
    echo "keepalive durdu"
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
      echo "calisiyor: $(tr '\n' ' ' < "$PIDFILE")"
    else
      echo "kapali"
    fi
    ;;
  *)
    echo "kullanim: $0 start|stop|status"
    exit 1
    ;;
esac
