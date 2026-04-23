import psutil
from datetime import datetime

IOCS = {"20.190.157.1", "34.98.64.218", "20.49.91.128", "34.237.6.16"}

print(f"=== IOC SCAN {datetime.now().strftime('%H:%M:%S')} ===")
hits = []
conns = []

for conn in psutil.net_connections(kind="inet"):
    if not conn.raddr:
        continue
    if conn.status not in ("ESTABLISHED", "SYN_SENT"):
        continue
    try:
        name = psutil.Process(conn.pid).name()
    except Exception:
        name = "unknown"
    rip = conn.raddr.ip
    if rip in IOCS:
        hits.append(f"  [IOC HIT] {name}({conn.pid}) -> {rip}:{conn.raddr.port} [{conn.status}]")
    conns.append((name, conn.pid, rip, conn.raddr.port))

print(f"IOC hits: {len(hits)}")
for h in hits:
    print(h)

print(f"\n=== ALL OUTBOUND ({len(conns)}) ===")
for name, pid, rip, port in sorted(conns):
    print(f"  {name:<35} ({pid:>6}) -> {rip:<20}:{port}")
