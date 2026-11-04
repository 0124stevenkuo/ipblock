#!/usr/bin/env python3
"""Build a Check Point IoC feed from the Palo Alto IP/CIDR blocklist."""
from pathlib import Path
import ipaddress

root = Path(__file__).resolve().parent.parent
source = root / "blockip.txt"
output = root / "blockip.csv"
allowlist = root / "protected_ips.txt"

def parse_lines(path: Path, allow_cidr: bool):
    if not path.exists():
        return []
    entries = []
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            if "/" in value:
                if not allow_cidr:
                    raise ValueError("CIDR is not supported in protected_ips.txt")
                item = ipaddress.ip_network(value, strict=False)
            else:
                item = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"{path.name}:{number}: invalid IP/network {value!r}: {exc}") from exc
        if item.version != 4 or not item.is_global:
            raise ValueError(f"{path.name}:{number}: non-public IPv4/network: {value}")
        entries.append(item)
    return entries

items = parse_lines(source, True)
protected = set(parse_lines(allowlist, False))
rows = {}
for item in items:
    network = isinstance(item, ipaddress.IPv4Network)
    start = item.network_address if network else item
    end = item.broadcast_address if network else item
    if any(int(start) <= int(p) <= int(end) for p in protected):
        # Do not accidentally block a protected WAN IP inside a subnet.
        raise SystemExit(f"Protected IP overlaps blocked range {item}; review blockip.txt")
    if start == end:
        value, kind = str(start), "IP"
    else:
        value, kind = f"{start}-{end}", "IP Range"
    rows[(int(start), int(end))] = (value, kind)

if not rows:
    raise SystemExit("Refusing to generate an empty feed")
output_rows = ["# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT"]
for (lo, hi), (value, kind) in sorted(rows.items()):
    name = "SOC-" + str(ipaddress.IPv4Address(lo)).replace(".", "-")
    if lo != hi:
        name += "-RANGE-" + str(ipaddress.IPv4Address(hi)).replace(".", "-")
    output_rows.append(f"{name},{value},{kind},high,high,AB,TREC-SOC")
data = "\n".join(output_rows) + "\n"
if not output.exists() or output.read_text(encoding="utf-8") != data:
    output.write_text(data, encoding="utf-8")
print(f"Input entries: {len(items)}, protected: {len(protected)}, feed: {len(rows)}")
