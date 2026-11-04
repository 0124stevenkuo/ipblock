#!/usr/bin/env python3
"""Build a Check Point IoC feed from the Palo Alto plain-IP blocklist."""
from pathlib import Path
import ipaddress

root = Path(__file__).resolve().parent.parent
source = root / "blockip.txt"
output = root / "blockip.csv"
allowlist = root / "protected_ips.txt"

def load_ips(path: Path) -> set[str]:
    if not path.exists():
        return set()
    result = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"{path.name}:{number}: invalid IP {value!r}") from exc
        if address.version != 4 or not address.is_global:
            raise ValueError(f"{path.name}:{number}: not a global IPv4: {value}")
        result.add(str(address))
    return result

ips = load_ips(source)
protected = load_ips(allowlist)
blocked = sorted(ips - protected, key=lambda value: int(ipaddress.ip_address(value)))
if not blocked:
    raise SystemExit("Refusing to generate an empty feed")
rows = ["# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT"]
rows += [
    f"SOC-{ip.replace('.', '-')},{ip},IP,high,high,AB,TREC-SOC"
    for ip in blocked
]
data = "\n".join(rows) + "\n"
if not output.exists() or output.read_text(encoding="utf-8") != data:
    output.write_text(data, encoding="utf-8")
print(f"Input: {len(ips)} unique IPs, protected: {len(protected)}, feed: {len(blocked)}")
