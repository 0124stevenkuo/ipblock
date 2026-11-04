#!/usr/bin/env python3
"""Keep T-REC blockip.txt safe and generate Check Point IoC CSV."""
from pathlib import Path
import ipaddress

root = Path(__file__).resolve().parent.parent
source = root / "blockip.txt"
output = root / "blockip.csv"
allowlist = root / "protected_ips.txt"

def parse(value, path, line):
    try:
        if "/" in value:
            obj = ipaddress.ip_network(value, strict=False)
        else:
            obj = ipaddress.ip_address(value)
    except ValueError as e:
        raise ValueError(f"{path}:{line}: invalid indicator {value}: {e}") from e
    if obj.version != 4 or not obj.is_global:
        raise ValueError(f"{path}:{line}: non-global IPv4 {value}")
    return obj

if not allowlist.exists():
    raise SystemExit("Missing protected_ips.txt: refusing to publish feed")
protected = set()
for i, line in enumerate(allowlist.read_text(encoding="utf-8-sig").splitlines(), 1):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    item = parse(line, allowlist.name, i)
    if isinstance(item, ipaddress.IPv4Network):
        raise SystemExit("protected_ips.txt must contain individual IPv4 addresses")
    protected.add(item)
if len(protected) != 26:
    raise SystemExit(f"Expected 26 protected addresses, found {len(protected)}; review before syncing")

lines = source.read_text(encoding="utf-8-sig").splitlines(keepends=True)
clean_lines = []
indicators = {}
removed = []
for i, original in enumerate(lines, 1):
    value = original.strip()
    if not value or value.startswith("#"):
        clean_lines.append(original)
        continue
    obj = parse(value, source.name, i)
    if isinstance(obj, ipaddress.IPv4Address) and obj in protected:
        removed.append(value)
        continue
    if isinstance(obj, ipaddress.IPv4Network):
        for ip in protected:
            if ip in obj:
                raise SystemExit(f"STOP: blocked CIDR {obj} contains protected {ip}; no output changed")
        start, end = obj.network_address, obj.broadcast_address
    else:
        start = end = obj
    indicators[(int(start), int(end))] = (start, end)
    clean_lines.append(original)

if not indicators:
    raise SystemExit("Refusing to create empty feed")
rows = ["# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT"]
for (lo, hi), (start, end) in sorted(indicators.items()):
    if lo == hi:
        value, kind = str(start), "IP"
        name = "SOC-" + str(start).replace(".", "-")
    else:
        value, kind = f"{start}-{end}", "IP Range"
        name = "SOC-" + str(start).replace(".", "-") + "-RANGE-" + str(end).replace(".", "-")
    rows.append(f"{name},{value},{kind},high,high,AB,TREC-SOC")

csv = "\n".join(rows) + "\n"
clean = "".join(clean_lines)
if removed:
    source.write_text(clean, encoding="utf-8")
    print(f"Removed {len(removed)} protected-IP entries from blockip.txt")
if not output.exists() or output.read_text(encoding="utf-8") != csv:
    output.write_text(csv, encoding="utf-8")
print(f"Protected: {len(protected)}; unique feed indicators: {len(indicators)}")
