import base64
import json
import os
import re
import ssl
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from typing import Any

from app.services.solidserver_tool import eip_request


REAL_QUERY_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "HTTPS", "SVCB"}
NOISE_QUERY_TYPES = {"DS", "DNSKEY", "SOA", "NS", "NSEC", "NSEC3", "RRSIG"}


def s(value: Any) -> str:
    return str(value or "").strip()


def is_truthy(value: Any) -> bool:
    return s(value).lower() in ("1", "true", "yes", "y", "on")


def is_reverse_zone(zone: str) -> bool:
    z = zone.lower()
    return z.endswith(".in-addr.arpa") or z.endswith(".ip6.arpa")


def has_graylog_auth() -> bool:
    return bool(
        os.getenv("GRAYLOG_TOKEN")
        or os.getenv("GRAYLOG_USER")
        or os.getenv("GRAYLOG_USERNAME")
    )


def smart_dns_name() -> str:
    return os.getenv("DNS_USAGE_SMART_NAME", "auth-dns-smart-middlebury.edu").strip().lower()


def graylog_base_url() -> str:
    return (os.getenv("GRAYLOG_BASE_URL") or "").rstrip("/")


def graylog_auth_header() -> str:
    token = os.getenv("GRAYLOG_TOKEN", "").strip()
    if token:
        raw = token + ":token"
        return "Basic " + base64.b64encode(raw.encode()).decode()

    user = os.getenv("GRAYLOG_USER") or os.getenv("GRAYLOG_USERNAME") or ""
    password = os.getenv("GRAYLOG_PASS") or os.getenv("GRAYLOG_PASSWORD") or ""
    if user and password:
        raw = user + ":" + password
        return "Basic " + base64.b64encode(raw.encode()).decode()

    return ""


def graylog_search(query: str, seconds: int, limit: int = 1) -> dict[str, Any]:
    base = graylog_base_url()
    auth = graylog_auth_header()

    if not base:
        raise RuntimeError("GRAYLOG_BASE_URL missing")
    if not auth:
        raise RuntimeError("GRAYLOG_TOKEN or Graylog credentials missing")

    url = (
        base
        + "/api/search/universal/relative?"
        + urllib.parse.urlencode(
            {
                "query": query,
                "range": str(seconds),
                "limit": str(limit),
                "sort": "timestamp:desc",
            }
        )
    )

    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "X-Requested-By": "netops-v4",
            "Authorization": auth,
        },
    )

    ctx = ssl._create_unverified_context()

    with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


_QUERY_RE = re.compile(r"view\s+External:\s+query.*?'([^']+)'", re.IGNORECASE)


def parse_query_name_type(message: str) -> tuple[str, str]:
    m = _QUERY_RE.search(message or "")
    if not m:
        return "", ""

    payload = m.group(1)
    parts = payload.split("/")
    name = parts[0].strip().rstrip(".").lower() if parts else ""
    qtype = parts[1].strip().upper() if len(parts) > 1 else ""
    return name, qtype


def zone_graylog_query(zone: str) -> str:
    # Only named/BIND External-view query logs.
    # Exclude SOLIDserver config/audit events and obvious denied cache noise.
    z = zone.replace('"', '\\"')
    return (
        f'(message:"view External" OR full_message:"view External") '
        f'AND (message:"query" OR full_message:"query") '
        f'AND (message:"{z}" OR full_message:"{z}") '
        f'AND NOT (message:"ipmserver" OR full_message:"ipmserver") '
        f'AND NOT (message:"dns_rr_add" OR full_message:"dns_rr_add") '
        f'AND NOT (message:"dns_rr_edit" OR full_message:"dns_rr_edit") '
        f'AND NOT (message:"dns_rr_delete" OR full_message:"dns_rr_delete") '
        f'AND NOT (message:"denied" OR full_message:"denied") '
        f'AND NOT (message:"allow-query-cache" OR full_message:"allow-query-cache")'
    )


def graylog_hits_for_zone(zone: str) -> dict[str, Any]:
    q = zone_graylog_query(zone)

    # Pull samples so we can separate real client/application query types from delegation/DNSSEC noise.
    data_24h = graylog_search(q, 86400, 100)
    data_7d = graylog_search(q, 604800, 250)
    data_30d = graylog_search(q, 2592000, 500)

    def count_real(data: dict[str, Any]) -> tuple[int, int, str, str, str]:
        real = 0
        noise = 0
        last_seen = ""
        names = Counter()
        types = Counter()

        for item in data.get("messages") or []:
            msg = item.get("message") or {}
            text = str(msg.get("message") or msg.get("full_message") or "")

            name, qtype = parse_query_name_type(text)
            if not qtype:
                continue

            if qtype in NOISE_QUERY_TYPES:
                noise += 1
                continue

            if qtype not in REAL_QUERY_TYPES:
                noise += 1
                continue

            real += 1

            if name:
                names[name] += 1
            if qtype:
                types[qtype] += 1
            if not last_seen:
                last_seen = s(msg.get("timestamp"))

        top_query = names.most_common(1)[0][0] if names else ""
        top_type = types.most_common(1)[0][0] if types else ""

        return real, noise, last_seen, top_query, top_type

    hits_24h, noise_24h, _, _, _ = count_real(data_24h)
    hits_7d, noise_7d, _, _, _ = count_real(data_7d)
    hits_30d, noise_30d, last_seen, top_query, top_type = count_real(data_30d)

    return {
        "hits_24h": hits_24h,
        "hits_7d": hits_7d,
        "hits_30d": hits_30d,
        "noise_24h": noise_24h,
        "noise_7d": noise_7d,
        "noise_30d": noise_30d,
        "last_seen": last_seen,
        "top_query": top_query,
        "top_type": top_type,
    }


def zone_source_priority(row: dict[str, Any]) -> tuple[int, str]:
    smart = smart_dns_name()
    dns_name = s(row.get("dns_name")).lower()
    dns_type = s(row.get("dns_type")).lower()
    parent = s(row.get("vdns_parent_name")).lower()
    zone_type = s(row.get("dnszone_type")).lower()

    if dns_name == smart or dns_type == "vdns":
        return (0, dns_name)

    if parent == smart:
        return (1, dns_name)

    if zone_type == "master":
        return (2, dns_name)

    return (3, dns_name)


def dedupe_zones_to_smart(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for row in rows:
        zone = s(row.get("dnszone_name") or row.get("dnszone_name_utf")).lower()
        view = s(row.get("dnsview_name")).lower()
        if zone:
            grouped[(zone, view)].append(row)

    out = []
    collapsed = 0

    for _, group in grouped.items():
        group = sorted(group, key=zone_source_priority)
        chosen = dict(group[0])
        chosen["_source_rows_collapsed"] = len(group)
        chosen["_source_dns_names"] = ", ".join(sorted({s(g.get("dns_name")) for g in group if s(g.get("dns_name"))}))
        collapsed += max(0, len(group) - 1)
        out.append(chosen)

    return out, collapsed


def rr_source_priority(row: dict[str, Any]) -> tuple[int, str]:
    smart = smart_dns_name()
    dns_name = s(row.get("dns_name")).lower()
    dns_type = s(row.get("dns_type")).lower()

    if dns_name == smart or dns_type == "vdns":
        return (0, dns_name)

    return (1, dns_name)


def dedupe_rrs_to_smart(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for row in rows:
        key = (
            s(row.get("dnszone_name") or row.get("dnszone_name_utf")).lower(),
            s(row.get("rr_type")).upper(),
            s(row.get("rr_full_name") or row.get("rr_full_name_utf")).lower(),
            s(row.get("rr_all_value") or row.get("value1")).lower(),
            s(row.get("ttl")),
        )
        if key[0]:
            grouped[key].append(row)

    out = []
    collapsed = 0

    for _, group in grouped.items():
        group = sorted(group, key=rr_source_priority)
        chosen = dict(group[0])
        chosen["_source_rows_collapsed"] = len(group)
        collapsed += max(0, len(group) - 1)
        out.append(chosen)

    return out, collapsed


def normalize_zone(row: dict[str, Any]) -> dict[str, Any]:
    zone = s(row.get("dnszone_name") or row.get("dnszone_name_utf"))
    return {
        "zone": zone,
        "zone_id": s(row.get("dnszone_id")),
        "view": s(row.get("dnsview_name")),
        "type": s(row.get("dnszone_type")),
        "dns": s(row.get("dns_name")),
        "masters": s(row.get("dnszone_masters")),
        "forwarders": s(row.get("dnszone_forwarders")),
        "is_reverse": is_truthy(row.get("dnszone_is_reverse")) or is_reverse_zone(zone),
        "enabled": s(row.get("row_enabled") or row.get("dns_state")),
        "xfer_done": s(row.get("dnszone_xfer_done")),
        "raw": row,
    }


def normalize_rr(row: dict[str, Any]) -> dict[str, Any]:
    rr_type = s(row.get("rr_type")).upper()
    zone = s(row.get("dnszone_name") or row.get("dnszone_name_utf"))
    name = s(row.get("rr_full_name") or row.get("rr_full_name_utf"))
    value = s(row.get("rr_all_value") or row.get("value1"))

    return {
        "zone": zone,
        "zone_id": s(row.get("dnszone_id")),
        "view": s(row.get("dnsview_name")),
        "name": name,
        "type": rr_type,
        "value": value,
        "ttl": s(row.get("ttl")),
        "raw": row,
    }


def classify_zone(zone_row: dict[str, Any], counts: Counter, hits_30d: int | None) -> tuple[str, str]:
    total = sum(counts.values())
    mx = counts.get("MX", 0)
    a = counts.get("A", 0)
    cname = counts.get("CNAME", 0)
    txt = counts.get("TXT", 0)
    ns = counts.get("NS", 0)

    if hits_30d is None:
        if mx > 0:
            return "REVIEW", "MX present; hit data unavailable"
        if total <= 4 and a == 0 and cname == 0 and mx == 0:
            return "PARKED?", "tiny zone; hit data unavailable"
        return "NO HIT DATA", "Graylog query unavailable"

    if hits_30d > 100:
        return "ACTIVE", "queries seen in last 30d"

    if hits_30d > 0:
        return "LOW", "low query volume"

    if mx > 0:
        return "REVIEW", "zero DNS hits but MX exists"

    if total <= 12 and a == 0 and cname <= 2 and txt <= 2 and ns >= 1:
        return "PARKED CANDIDATE", "zero hits and minimal records"

    return "ZERO HITS", "zero queries in selected window"


def dns_usage_context(limit_zones: int = 5000, limit_rr: int = 100000, q: str = "") -> dict[str, Any]:
    q_l = s(q).lower()
    errors = []

    try:
        zone_rows_raw = eip_request("dns_zone_list", "dnsview_name='External'", limit_zones)
    except Exception as exc:
        zone_rows_raw = []
        errors.append(f"SOLIDserver zone query failed: {exc}")

    try:
        rr_rows_raw = eip_request("dns_rr_list", "dnsview_name='External'", limit_rr)
    except Exception as exc:
        rr_rows_raw = []
        errors.append(f"SOLIDserver RR query failed: {exc}")

    zone_rows_raw_count = len(zone_rows_raw)
    rr_rows_raw_count = len(rr_rows_raw)

    zone_rows_raw, zone_rows_collapsed = dedupe_zones_to_smart(zone_rows_raw)
    rr_rows_raw, rr_rows_collapsed = dedupe_rrs_to_smart(rr_rows_raw)

    zones_all = [normalize_zone(r) for r in zone_rows_raw]
    zones = [z for z in zones_all if not z["is_reverse"]]
    reverse_hidden = len(zones_all) - len(zones)

    rrs = [normalize_rr(r) for r in rr_rows_raw]

    rr_by_zone: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rr in rrs:
        if rr["zone"]:
            rr_by_zone[rr["zone"]].append(rr)

    graylog_enabled = bool(graylog_base_url() and has_graylog_auth())
    graylog_error_count = 0

    rows = []

    for z in zones:
        zone = z["zone"]
        zone_rrs = rr_by_zone.get(zone, [])
        counts = Counter(r["type"] for r in zone_rrs if r["type"])

        hits_24h = None
        hits_7d = None
        hits_30d = None
        last_seen = ""
        top_query = ""
        top_type = ""
        noise_24h = None
        noise_7d = None
        noise_30d = None

        if graylog_enabled:
            try:
                hit_data = graylog_hits_for_zone(zone)
                hits_24h = hit_data["hits_24h"]
                hits_7d = hit_data["hits_7d"]
                hits_30d = hit_data["hits_30d"]
                last_seen = hit_data["last_seen"]
                top_query = hit_data["top_query"]
                top_type = hit_data["top_type"]
                noise_24h = hit_data.get("noise_24h")
                noise_7d = hit_data.get("noise_7d")
                noise_30d = hit_data.get("noise_30d")
            except Exception as exc:
                graylog_error_count += 1
                if graylog_error_count <= 5:
                    errors.append(f"Graylog hit query failed for {zone}: {exc}")

        status, note = classify_zone(z, counts, hits_30d)

        row = {
            "zone": zone,
            "zone_id": z["zone_id"],
            "view": z["view"],
            "zone_type": z["type"],
            "records": sum(counts.values()),
            "a": counts.get("A", 0),
            "aaaa": counts.get("AAAA", 0),
            "cname": counts.get("CNAME", 0),
            "mx": counts.get("MX", 0),
            "txt": counts.get("TXT", 0),
            "ns": counts.get("NS", 0),
            "soa": counts.get("SOA", 0),
            "ptr": counts.get("PTR", 0),
            "hits_24h": hits_24h,
            "hits_7d": hits_7d,
            "hits_30d": hits_30d,
            "last_seen": last_seen,
            "top_query": top_query,
            "top_type": top_type,
            "noise_24h": noise_24h,
            "noise_7d": noise_7d,
            "noise_30d": noise_30d,
            "status": status,
            "note": note,
            "is_reverse": z["is_reverse"],
        }

        if q_l and q_l not in zone.lower() and q_l not in status.lower() and q_l not in note.lower():
            continue

        rows.append(row)

    def status_order(row):
        order = {
            "PARKED CANDIDATE": 0,
            "PARKED?": 1,
            "ZERO HITS": 2,
            "NO HIT DATA": 3,
            "LOW": 4,
            "REVIEW": 5,
            "ACTIVE": 6,
        }
        return (order.get(row["status"], 9), row["zone"])

    rows.sort(key=status_order)

    summary = {
        "zones": len(rows),
        "external_zones_total": len(zones),
        "records": sum(r["records"] for r in rows),
        "no_hit_data": sum(1 for r in rows if r["status"] == "NO HIT DATA"),
        "parked": sum(1 for r in rows if r["status"] in ("PARKED?", "PARKED CANDIDATE")),
        "zero_hits": sum(1 for r in rows if r["status"] == "ZERO HITS"),
        "low": sum(1 for r in rows if r["status"] == "LOW"),
        "active": sum(1 for r in rows if r["status"] == "ACTIVE"),
        "with_mx": sum(1 for r in rows if r["mx"] > 0),
        "graylog_auth": has_graylog_auth(),
        "graylog_enabled": graylog_enabled,
        "graylog_errors": graylog_error_count,
        "smart_name": smart_dns_name(),
        "zone_source_rows": zone_rows_raw_count,
        "rr_source_rows": rr_rows_raw_count,
        "zone_rows_collapsed": zone_rows_collapsed,
        "rr_rows_collapsed": rr_rows_collapsed,
        "reverse_hidden": reverse_hidden,
    }

    if graylog_enabled:
        hit_note = (
            "Graylog hit counts enabled. Real hits exclude DS/DNSKEY/SOA/NS delegation and DNSSEC noise. "
            "For zones delegated to Cloudflare, public query volume will still be undercounted here because traffic is served by Cloudflare authoritative DNS."
        )
    else:
        hit_note = "Graylog hit counts unavailable. Check GRAYLOG_BASE_URL and GRAYLOG_TOKEN."

    return {
        "title": "DNS External Zone Usage",
        "rows": rows,
        "summary": summary,
        "errors": errors,
        "q": q,
        "limit_zones": limit_zones,
        "limit_rr": limit_rr,
        "hit_note": hit_note,
    }


def dns_usage_csv(context: dict[str, Any]) -> str:
    import csv
    import io

    fields = [
        ("zone", "Zone"),
        ("records", "Records"),
        ("a", "A"),
        ("aaaa", "AAAA"),
        ("cname", "CNAME"),
        ("mx", "MX"),
        ("txt", "TXT"),
        ("ns", "NS"),
        ("ptr", "PTR"),
        ("hits_24h", "Hits 24h"),
        ("hits_7d", "Hits 7d"),
        ("hits_30d", "Hits 30d"),
        ("last_seen", "Last Seen"),
        ("top_query", "Top Query"),
        ("top_type", "Top Type"),
        ("status", "Status"),
        ("note", "Note"),
    ]

    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["DNS External Zone Usage"])
    writer.writerow(["Smart source", context.get("summary", {}).get("smart_name", "")])
    writer.writerow(["Hidden reverse zones", context.get("summary", {}).get("reverse_hidden", "")])
    writer.writerow(["Zone rows collapsed", context.get("summary", {}).get("zone_rows_collapsed", "")])
    writer.writerow(["RR rows collapsed", context.get("summary", {}).get("rr_rows_collapsed", "")])
    writer.writerow(["Hit note", context.get("hit_note", "")])
    writer.writerow([])

    writer.writerow([label for _, label in fields])

    for row in context.get("rows", []):
        writer.writerow([
            "" if row.get(key) is None else row.get(key, "")
            for key, _ in fields
        ])

    return buf.getvalue()
