import subprocess
from typing import Any


DEFAULT_ZONE = "middlebury.edu"
DEFAULT_HOST = "catalog.middlebury.edu"
DEFAULT_QTYPE = "A"

DEFAULT_CF_NS = "ns0245.secondary.cloudflare.com,ns0045.secondary.cloudflare.com"
DEFAULT_PARENT_SERVERS = "a.edu-servers.net,h.edu-servers.net"
DEFAULT_PUBLIC_RESOLVERS = "1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222"
DEFAULT_CAMPUS_RESOLVERS = "140.233.1.4,140.233.2.204"

VALID_QTYPES = [
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "SOA",
    "TXT",
    "PTR",
]


def split_csv(value: str) -> list[str]:
    return [x.strip() for x in str(value or "").split(",") if x.strip()]


def normalize_name(value: str) -> str:
    return str(value or "").strip().rstrip(".").lower()


def display_name(value: str) -> str:
    return str(value or "").strip().rstrip(".")


def parse_dig_lines(output: str) -> list[dict[str, Any]]:
    rows = []

    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        name = parts[0].rstrip(".")
        ttl = parts[1]
        rrclass = parts[2]
        rrtype = parts[3]
        value = " ".join(parts[4:])

        if rrtype in ("NS", "CNAME", "PTR"):
            value = value.rstrip(".")
        elif rrtype == "MX":
            mx_parts = value.split()
            if len(mx_parts) >= 2:
                value = mx_parts[0] + " " + mx_parts[1].rstrip(".")

        rows.append({
            "name": name,
            "ttl": ttl,
            "class": rrclass,
            "type": rrtype,
            "value": value,
        })

    return rows


def dig(server: str, qname: str, qtype: str, recursion: bool = True) -> tuple[str, list[dict[str, Any]], str]:
    cmd = [
        "dig",
        "+time=2",
        "+tries=1",
        "+nocmd",
        "+noall",
        "+answer",
        "+authority",
        f"@{server}",
        qname,
        qtype,
    ]

    if not recursion:
        cmd.insert(5, "+norecurse")

    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", [], "query timed out"
    except Exception as exc:
        return "ERROR", [], str(exc)

    output = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    rows = parse_dig_lines(output)

    if rows:
        return "OK", rows, ""

    if err:
        return "ERROR", [], err

    return "NO_ANSWER", [], ""


def make_issue_row(server: str, check: str, qname: str, qtype: str, status: str, value: str = "") -> dict[str, Any]:
    return {
        "server": server,
        "check": check,
        "name": qname,
        "type": qtype,
        "ttl": "",
        "status": status,
        "value": value,
        "status_class": "bad",
    }


def run_check(
    server: str,
    check: str,
    qname: str,
    qtype: str,
    recursion: bool,
    expected_values: set[str] | None = None,
    strict_expected: bool = False,
) -> list[dict[str, Any]]:
    status, records, err = dig(server, qname, qtype, recursion=recursion)

    if not records:
        return [make_issue_row(server, check, qname, qtype, status, err)]

    rows = []

    for rec in records:
        value_norm = normalize_name(rec.get("value", ""))

        row_status = "OK"
        row_class = "good"

        if strict_expected and expected_values is not None:
            if value_norm not in expected_values:
                row_status = "ISSUE"
                row_class = "bad"

        rows.append({
            "server": server,
            "check": check,
            "name": rec.get("name", ""),
            "type": rec.get("type", ""),
            "ttl": rec.get("ttl", ""),
            "status": row_status,
            "value": rec.get("value", ""),
            "status_class": row_class,
        })

    return rows


def section(title: str, subtitle: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok = sum(1 for r in rows if r.get("status") == "OK")
    issues = len(rows) - ok

    return {
        "title": title,
        "subtitle": subtitle,
        "rows": rows,
        "row_count": len(rows),
        "ok_count": ok,
        "issue_count": issues,
    }


def dns_domain_check_context(
    zone: str = DEFAULT_ZONE,
    host: str = DEFAULT_HOST,
    qtype: str = DEFAULT_QTYPE,
    cf_ns: str = DEFAULT_CF_NS,
    parent_servers: str = DEFAULT_PARENT_SERVERS,
    public_resolvers: str = DEFAULT_PUBLIC_RESOLVERS,
    campus_resolvers: str = DEFAULT_CAMPUS_RESOLVERS,
) -> dict[str, Any]:
    zone = display_name(zone or DEFAULT_ZONE)
    host = display_name(host or zone)
    qtype = str(qtype or DEFAULT_QTYPE).upper().strip()

    if qtype not in VALID_QTYPES:
        qtype = DEFAULT_QTYPE

    cf_servers = split_csv(cf_ns or DEFAULT_CF_NS)
    parent = split_csv(parent_servers or DEFAULT_PARENT_SERVERS)
    public = split_csv(public_resolvers or DEFAULT_PUBLIC_RESOLVERS)
    campus = split_csv(campus_resolvers or DEFAULT_CAMPUS_RESOLVERS)

    expected_cf_ns = {normalize_name(x) for x in cf_servers}

    sections = []

    rows = []
    for server in cf_servers:
        rows.extend(run_check(server, f"SOA {zone}", zone, "SOA", recursion=False))
        rows.extend(run_check(server, f"NS {zone}", zone, "NS", recursion=False, expected_values=expected_cf_ns, strict_expected=True))
        rows.extend(run_check(server, f"{qtype} {host}", host, qtype, recursion=False))

    sections.append(section(
        "1. Cloudflare authoritative secondary check",
        "Direct SOA, NS, and record checks against the Cloudflare secondary authoritative nameservers.",
        rows,
    ))

    rows = []
    for server in parent:
        rows.extend(run_check(server, f"NS {zone}", zone, "NS", recursion=False, expected_values=expected_cf_ns, strict_expected=True))

    sections.append(section(
        "2. Parent delegation check",
        "Direct NS checks against the parent nameservers. Delegation records usually appear in the Authority section.",
        rows,
    ))

    rows = []
    for server in public:
        rows.extend(run_check(server, f"NS {zone}", zone, "NS", recursion=True, expected_values=expected_cf_ns, strict_expected=True))

    sections.append(section(
        "3. Public recursive resolver NS propagation",
        "NS checks against public recursive resolvers.",
        rows,
    ))

    rows = []
    for server in public:
        rows.extend(run_check(server, f"{qtype} {host}", host, qtype, recursion=True))

    sections.append(section(
        "4. Public recursive host / record resolution",
        f"{qtype} checks against public recursive resolvers.",
        rows,
    ))

    rows = []
    for server in campus:
        rows.extend(run_check(server, f"NS {zone}", zone, "NS", recursion=True))
        rows.extend(run_check(server, f"{qtype} {host}", host, qtype, recursion=True))

    sections.append(section(
        "5. Campus resolver comparison",
        "Campus/internal resolver comparison. These answers may intentionally differ from public DNS because of split-horizon DNS.",
        rows,
    ))

    total_rows = sum(s["row_count"] for s in sections)
    total_ok = sum(s["ok_count"] for s in sections)
    total_issues = sum(s["issue_count"] for s in sections)

    return {
        "title": "DNS Domain Check",
        "zone": zone,
        "host": host,
        "qtype": qtype,
        "qtypes": VALID_QTYPES,
        "cf_ns": ",".join(cf_servers),
        "parent_servers": ",".join(parent),
        "public_resolvers": ",".join(public),
        "campus_resolvers": ",".join(campus),
        "sections": sections,
        "total_rows": total_rows,
        "total_ok": total_ok,
        "total_issues": total_issues,
    }
