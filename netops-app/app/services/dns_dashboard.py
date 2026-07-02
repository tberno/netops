import os
import random
import socket
import struct
import time
from typing import Any


QTYPE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}


def env_list(name: str, default: str) -> list[str]:
    value = os.environ.get(name, default)
    return [x.strip().rstrip(".") for x in value.split(",") if x.strip()]


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    out = b""
    for part in name.split("."):
        b = part.encode("utf-8")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    original_offset = offset
    seen = set()

    while True:
        if offset >= len(data):
            return ".".join(labels), offset

        length = data[offset]

        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                return ".".join(labels), offset + 1

            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in seen:
                return ".".join(labels), offset + 2
            seen.add(ptr)

            if not jumped:
                original_offset = offset + 2
                jumped = True

            offset = ptr
            continue

        offset += 1
        label = data[offset:offset + length].decode("utf-8", errors="replace")
        labels.append(label)
        offset += length

    return ".".join(labels), (original_offset if jumped else offset)


def parse_record(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    name, offset = read_name(data, offset)

    if offset + 10 > len(data):
        return {"name": name, "error": "truncated record"}, len(data)

    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10

    rdata_offset = offset
    rdata = data[offset:offset + rdlen]
    offset += rdlen

    value = ""
    extra = {}

    try:
        if rtype == 1 and len(rdata) == 4:
            value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28 and len(rdata) == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5, 12):
            value, _ = read_name(data, rdata_offset)
        elif rtype == 6:
            mname, pos = read_name(data, rdata_offset)
            rname, pos = read_name(data, pos)
            if pos + 20 <= len(data):
                serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[pos:pos + 20])
                value = f"{mname} serial {serial}"
                extra = {
                    "mname": mname,
                    "rname": rname,
                    "serial": serial,
                    "refresh": refresh,
                    "retry": retry,
                    "expire": expire,
                    "minimum": minimum,
                }
            else:
                value = mname
        elif rtype == 15:
            if len(rdata) >= 2:
                pref = struct.unpack("!H", rdata[:2])[0]
                mx, _ = read_name(data, rdata_offset + 2)
                value = f"{pref} {mx}"
        elif rtype == 16:
            chunks = []
            pos = 0
            while pos < len(rdata):
                ln = rdata[pos]
                pos += 1
                chunks.append(rdata[pos:pos + ln].decode("utf-8", errors="replace"))
                pos += ln
            value = "".join(chunks)
        else:
            value = rdata.hex()
    except Exception as exc:
        value = f"parse error: {exc}"

    type_name = next((k for k, v in QTYPE.items() if v == rtype), str(rtype))

    return {
        "name": name,
        "type": type_name,
        "type_num": rtype,
        "class": rclass,
        "ttl": ttl,
        "value": value,
        **extra,
    }, offset


def dns_query(server: str, qname: str, qtype: str = "SOA", timeout: float = 2.0) -> dict[str, Any]:
    qtype_num = QTYPE.get(qtype.upper(), 6)
    query_id = random.randint(0, 65535)

    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    packet += encode_name(qname)
    packet += struct.pack("!HH", qtype_num, 1)

    start = time.perf_counter()

    try:
        addrs = socket.getaddrinfo(server, 53, type=socket.SOCK_DGRAM)
        target = addrs[0][4]
    except Exception as exc:
        return {
            "server": server,
            "qname": qname,
            "qtype": qtype,
            "ok": False,
            "status": "RESOLVE_FAIL",
            "response_ms": "",
            "error": str(exc),
            "answers": [],
        }

    try:
        with socket.socket(socket.AF_INET if len(target) == 2 else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, target)
            data, _ = sock.recvfrom(4096)

        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)

        if len(data) < 12:
            raise RuntimeError("short DNS response")

        rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        rcode = flags & 0x000F

        offset = 12

        for _ in range(qd):
            _, offset = read_name(data, offset)
            offset += 4

        answers = []
        for _ in range(an):
            rec, offset = parse_record(data, offset)
            answers.append(rec)

        return {
            "server": server,
            "qname": qname,
            "qtype": qtype,
            "ok": rcode == 0 and bool(answers),
            "status": "OK" if rcode == 0 else f"RCODE_{rcode}",
            "response_ms": elapsed_ms,
            "error": "",
            "answers": answers,
        }

    except socket.timeout:
        return {
            "server": server,
            "qname": qname,
            "qtype": qtype,
            "ok": False,
            "status": "TIMEOUT",
            "response_ms": "",
            "error": "timeout",
            "answers": [],
        }
    except Exception as exc:
        return {
            "server": server,
            "qname": qname,
            "qtype": qtype,
            "ok": False,
            "status": "ERROR",
            "response_ms": "",
            "error": str(exc),
            "answers": [],
        }


def serial_from_result(result: dict[str, Any]) -> int | None:
    for ans in result.get("answers", []):
        serial = ans.get("serial")
        if isinstance(serial, int):
            return serial
    return None


def primary_from_result(result: dict[str, Any]) -> str:
    for ans in result.get("answers", []):
        if ans.get("mname"):
            return str(ans.get("mname"))
    return ""


def values_from_result(result: dict[str, Any]) -> list[str]:
    out = []
    for ans in result.get("answers", []):
        val = ans.get("value", "")
        if val:
            out.append(str(val))
    return out


def soa_row(label: str, server: str, zone: str, expected_serial: int | None = None) -> dict[str, Any]:
    result = dns_query(server, zone, "SOA", timeout=2.0)
    serial = serial_from_result(result)

    row = {
        "role": label,
        "server": server,
        "status": result["status"],
        "response_ms": result["response_ms"],
        "serial": serial if serial is not None else "",
        "serial_int": serial,
        "sync": "unknown",
        "delta": "",
        "primary": primary_from_result(result),
        "soa": "; ".join(values_from_result(result)),
        "error": result["error"],
    }

    if result["status"] != "OK" or serial is None or expected_serial is None:
        row["sync"] = "unknown" if result["status"] == "OK" else "error"
    elif serial == expected_serial:
        row["sync"] = "current"
        row["delta"] = 0
    elif serial < expected_serial:
        row["sync"] = "cached"
        row["delta"] = expected_serial - serial
    else:
        row["sync"] = "ahead"
        row["delta"] = serial - expected_serial

    return row


def ns_row(label: str, server: str, zone: str, expected_ns: set[str]) -> dict[str, Any]:
    result = dns_query(server, zone, "NS", timeout=2.0)
    values = sorted(v.rstrip(".").lower() for v in values_from_result(result))
    got = set(values)

    missing = sorted(expected_ns - got)
    extra = sorted(got - expected_ns)

    if result["status"] != "OK":
        check = "Error"
    elif not missing and not extra:
        check = "OK"
    else:
        check = "Mismatch"

    return {
        "resolver": label,
        "server": server,
        "status": result["status"],
        "response_ms": result["response_ms"],
        "ns_values": ", ".join(values),
        "check": check,
        "missing": ", ".join(missing),
        "extra": ", ".join(extra),
        "error": result["error"],
    }


def dns_dashboard_context(zone: str | None = None) -> dict[str, Any]:
    zones = env_list("DNS_DASHBOARD_ZONES", "middlebury.edu")
    zone = (zone or zones[0]).strip().rstrip(".")

    secondaries = [
        {"name": "Cloudflare Secondary 0245", "server": "ns0245.secondary.cloudflare.com"},
        {"name": "Cloudflare Secondary 0045", "server": "ns0045.secondary.cloudflare.com"},
    ]

    resolvers = [
        {"name": "Cloudflare 1.1.1.1", "server": "1.1.1.1"},
        {"name": "Google 8.8.8.8", "server": "8.8.8.8"},
        {"name": "Quad9 9.9.9.9", "server": "9.9.9.9"},
    ]

    internal_reference = [
        {"name": "Hera / internal view", "server": os.environ.get("DNS_HERA", "140.233.2.204")},
        {"name": "Zeus / internal view", "server": os.environ.get("DNS_ZEUS", "140.233.1.4")},
    ]

    # First pass: collect Cloudflare secondary serials.
    cf_probe_rows = [soa_row(x["name"], x["server"], zone, None) for x in secondaries]
    cf_good_serials = [
        r["serial_int"] for r in cf_probe_rows
        if r["status"] == "OK" and r.get("serial_int") is not None
    ]

    cf_serials_match = len(cf_good_serials) == len(secondaries) and len(set(cf_good_serials)) == 1
    cf_expected_serial = cf_good_serials[0] if cf_serials_match else (max(cf_good_serials) if cf_good_serials else None)

    cf_rows = [soa_row(x["name"], x["server"], zone, cf_expected_serial) for x in secondaries]

    public_rows = []
    public_serials = []

    for item in resolvers:
        soa = dns_query(item["server"], zone, "SOA", timeout=2.0)
        ns = dns_query(item["server"], zone, "NS", timeout=2.0)
        serial = serial_from_result(soa)

        if serial is not None:
            public_serials.append(serial)

        sync = "unknown"
        delta = ""

        if soa["status"] != "OK" or serial is None or cf_expected_serial is None:
            sync = "unknown" if soa["status"] == "OK" else "error"
        elif serial == cf_expected_serial:
            sync = "current"
            delta = 0
        elif serial < cf_expected_serial:
            sync = "cached"
            delta = cf_expected_serial - serial
        else:
            sync = "ahead"
            delta = serial - cf_expected_serial

        public_rows.append({
            "resolver": item["name"],
            "server": item["server"],
            "soa_status": soa["status"],
            "soa_ms": soa["response_ms"],
            "soa_serial": serial or "",
            "sync": sync,
            "delta": delta,
            "primary": primary_from_result(soa),
            "ns_status": ns["status"],
            "ns_ms": ns["response_ms"],
            "ns_values": ", ".join(values_from_result(ns)[:8]),
        })

    expected_ns = {
        "ns0045.secondary.cloudflare.com",
        "ns0245.secondary.cloudflare.com",
    }

    ns_rows = [ns_row(x["name"], x["server"], zone, expected_ns) for x in resolvers]

    internal_rows = []
    for item in internal_reference:
        row = soa_row(item["name"], item["server"], zone, None)
        row["sync"] = "reference"
        row["delta"] = ""
        internal_rows.append(row)

    cf_ok = sum(1 for r in cf_rows if r["status"] == "OK" and r["sync"] == "current")
    cf_bad = len(cf_rows) - cf_ok

    resolver_ok = sum(
        1 for r in public_rows
        if r["soa_status"] == "OK" and r["ns_status"] == "OK" and r["sync"] == "current"
    )
    resolver_bad = len(public_rows) - resolver_ok

    ns_ok = sum(1 for r in ns_rows if r["check"] == "OK")
    ns_bad = len(ns_rows) - ns_ok

    zone_rows = []

    for z in zones:
        z = z.strip().rstrip(".")
        if not z:
            continue

        cf1 = soa_row("CF0245", "ns0245.secondary.cloudflare.com", z, None)
        cf2 = soa_row("CF0045", "ns0045.secondary.cloudflare.com", z, None)

        pub_serials = []
        for resolver in resolvers:
            r = dns_query(resolver["server"], z, "SOA", timeout=2.0)
            rs = serial_from_result(r)
            if rs is not None:
                pub_serials.append(rs)

        serial_set = {
            x for x in [cf1["serial_int"], cf2["serial_int"], *pub_serials]
            if x is not None
        }

        if not serial_set:
            status = "unknown"
        elif len(serial_set) == 1:
            status = "external in sync"
        else:
            status = "public drift"

        zone_rows.append({
            "zone": z,
            "cf_0245": cf1["serial"] or cf1["status"],
            "cf_0045": cf2["serial"] or cf2["status"],
            "public_resolver_serials": ", ".join(str(x) for x in sorted(set(pub_serials))),
            "status": status,
        })

    # Overall status should represent authoritative/public delegation health.
    # Public recursive resolvers can legitimately lag because of caching, so keep
    # resolver SOA serial drift visible but do not make the whole dashboard red.
    overall_ok = cf_bad == 0 and ns_bad == 0

    public_soa_current = sum(1 for r in public_rows if r.get("sync") == "current")
    public_soa_total = len(public_rows)

    # For the smart-display KPI, reachable is more useful than cache freshness.
    # Recursive resolvers may answer an older SOA serial until TTL expires.
    public_soa_reachable = sum(1 for r in public_rows if r.get("soa_status") == "OK")

    return {
        "zone": zone,
        "zones": zones,

        "overall_ok": overall_ok,
        "external_serial": cf_expected_serial or "",

        "cf_total": len(cf_rows),
        "cf_ok": cf_ok,
        "cf_bad": cf_bad,
        "cf_serials_match": cf_serials_match,

        "resolver_total": len(public_rows),
        "resolver_ok": resolver_ok,
        "resolver_bad": resolver_bad,
        "public_soa_current": public_soa_current,
        "public_soa_total": public_soa_total,
        "public_soa_reachable": public_soa_reachable,

        "ns_total": len(ns_rows),
        "ns_ok": ns_ok,
        "ns_bad": ns_bad,

        "cf_rows": cf_rows,
        "public_rows": public_rows,
        "ns_rows": ns_rows,
        "internal_rows": internal_rows,
        "zone_rows": zone_rows,

        "cache_seconds": 0,
    }

# --- DNS dashboard add-on: internal authoritative response times ---
_dns_dashboard_context_base = dns_dashboard_context


def _parse_named_server_list(value: str) -> list[dict[str, str]]:
    rows = []

    for item in str(value or "").split(","):
        item = item.strip()
        if not item:
            continue

        if "=" in item:
            name, server = item.split("=", 1)
            rows.append({"name": name.strip(), "server": server.strip()})
        else:
            rows.append({"name": item, "server": item})

    return rows


def dns_dashboard_context(zone: str | None = None) -> dict[str, Any]:
    ctx = _dns_dashboard_context_base(zone)
    z = str(ctx.get("zone") or zone or "middlebury.edu").strip().rstrip(".")

    default_internal = (
        "Hera=hera.middlebury.edu,"
        "Zeus=zeus.middlebury.edu,"
        "MIIS Infoblox 1=miis-infoblox1.middlebury.edu,"
        "MIIS Infoblox 2=miis-infoblox2.middlebury.edu"
    )

    internal_servers = _parse_named_server_list(
        os.environ.get("DNS_INTERNAL_RESPONSE_SERVERS", default_internal)
    )

    rows = []

    for item in internal_servers:
        row = soa_row(item["name"], item["server"], z, None)
        row["sync"] = "reference"
        row["delta"] = ""
        row["role"] = item["name"]
        row["server"] = item["server"]
        rows.append(row)

    ok_rows = [r for r in rows if r.get("status") == "OK"]
    ms_values = []

    for r in ok_rows:
        try:
            ms_values.append(float(r.get("response_ms")))
        except Exception:
            pass

    avg_ms = round(sum(ms_values) / len(ms_values), 1) if ms_values else ""

    ctx["internal_latency_rows"] = rows
    ctx["internal_latency_total"] = len(rows)
    ctx["internal_latency_ok"] = len(ok_rows)
    ctx["internal_latency_bad"] = len(rows) - len(ok_rows)
    ctx["internal_latency_avg_ms"] = avg_ms

    return ctx


# --- DNS dashboard add-on: replace internal average with reachability/slowest ---
_dns_dashboard_context_with_internal_latency = dns_dashboard_context


def dns_dashboard_context(zone: str | None = None) -> dict[str, Any]:
    ctx = _dns_dashboard_context_with_internal_latency(zone)

    rows = ctx.get("internal_latency_rows", []) or []

    ok_rows = [r for r in rows if r.get("status") == "OK"]
    slowest = None

    for r in ok_rows:
        try:
            ms = float(r.get("response_ms"))
        except Exception:
            continue

        if slowest is None or ms > slowest["ms"]:
            slowest = {
                "ms": ms,
                "name": r.get("role") or r.get("server") or "unknown",
                "server": r.get("server") or "",
            }

    ctx["internal_latency_slowest_ms"] = round(slowest["ms"], 1) if slowest else ""
    ctx["internal_latency_slowest_name"] = slowest["name"] if slowest else ""

    # Broad status for mixed local + remote DNS. This is not meant to judge WAN latency harshly.
    if not slowest:
        ctx["internal_latency_state"] = "bad"
    elif slowest["ms"] >= 250:
        ctx["internal_latency_state"] = "bad"
    elif slowest["ms"] >= 100:
        ctx["internal_latency_state"] = "warn"
    else:
        ctx["internal_latency_state"] = "good"

    return ctx


# --- DNS dashboard add-on: split local VT DNS latency from remote CA reachability ---
_dns_dashboard_context_before_vt_ca_split = dns_dashboard_context


def _row_is_ca_dns(row: dict[str, Any]) -> bool:
    text = " ".join([
        str(row.get("role", "")),
        str(row.get("server", "")),
    ]).lower()

    return "miis" in text or "infoblox" in text


def _latency_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok_rows = [r for r in rows if r.get("status") == "OK"]
    slowest = None

    for r in ok_rows:
        try:
            ms = float(r.get("response_ms"))
        except Exception:
            continue

        if slowest is None or ms > slowest["ms"]:
            slowest = {
                "ms": ms,
                "name": r.get("role") or r.get("server") or "unknown",
            }

    if not slowest:
        state = "bad"
        slowest_ms = ""
        slowest_name = ""
    elif slowest["ms"] >= 100:
        state = "warn"
        slowest_ms = round(slowest["ms"], 1)
        slowest_name = slowest["name"]
    else:
        state = "good"
        slowest_ms = round(slowest["ms"], 1)
        slowest_name = slowest["name"]

    return {
        "total": len(rows),
        "ok": len(ok_rows),
        "bad": len(rows) - len(ok_rows),
        "slowest_ms": slowest_ms,
        "slowest_name": slowest_name,
        "state": state,
    }


def dns_dashboard_context(zone: str | None = None) -> dict[str, Any]:
    ctx = _dns_dashboard_context_before_vt_ca_split(zone)

    all_internal_rows = ctx.get("internal_latency_rows", []) or []

    vt_rows = [r for r in all_internal_rows if not _row_is_ca_dns(r)]
    ca_rows = [r for r in all_internal_rows if _row_is_ca_dns(r)]

    vt = _latency_stats(vt_rows)
    ca = _latency_stats(ca_rows)

    # Existing template variables now represent local VT DNS only.
    ctx["internal_latency_rows"] = vt_rows
    ctx["internal_latency_total"] = vt["total"]
    ctx["internal_latency_ok"] = vt["ok"]
    ctx["internal_latency_bad"] = vt["bad"]
    ctx["internal_latency_slowest_ms"] = vt["slowest_ms"]
    ctx["internal_latency_slowest_name"] = vt["slowest_name"]
    ctx["internal_latency_state"] = vt["state"]

    # New CA section is remote reachability from raccoon, not local CA latency.
    ctx["ca_dns_rows"] = ca_rows
    ctx["ca_dns_total"] = ca["total"]
    ctx["ca_dns_ok"] = ca["ok"]
    ctx["ca_dns_bad"] = ca["bad"]
    ctx["ca_dns_slowest_ms"] = ca["slowest_ms"]
    ctx["ca_dns_slowest_name"] = ca["slowest_name"]
    ctx["ca_dns_state"] = ca["state"]

    return ctx


# --- DNS dashboard add-on: show all internal DNS servers together ---
_dns_dashboard_context_before_show_all_internal = dns_dashboard_context


def dns_dashboard_context(zone: str | None = None) -> dict[str, Any]:
    ctx = _dns_dashboard_context_before_show_all_internal(zone)

    # Previous pass split MIIS into ca_dns_rows. For now, combine everything
    # back into one internal DNS response table.
    vt_rows = ctx.get("internal_latency_rows", []) or []
    ca_rows = ctx.get("ca_dns_rows", []) or []
    rows = vt_rows + ca_rows

    ok_rows = [r for r in rows if r.get("status") == "OK"]

    slowest = None
    for r in ok_rows:
        try:
            ms = float(r.get("response_ms"))
        except Exception:
            continue

        if slowest is None or ms > slowest["ms"]:
            slowest = {
                "ms": ms,
                "name": r.get("role") or r.get("server") or "unknown",
            }

    if not slowest:
        state = "bad"
        slowest_ms = ""
        slowest_name = ""
    elif slowest["ms"] >= 250:
        state = "bad"
        slowest_ms = round(slowest["ms"], 1)
        slowest_name = slowest["name"]
    elif slowest["ms"] >= 100:
        state = "warn"
        slowest_ms = round(slowest["ms"], 1)
        slowest_name = slowest["name"]
    else:
        state = "good"
        slowest_ms = round(slowest["ms"], 1)
        slowest_name = slowest["name"]

    ctx["internal_latency_rows"] = rows
    ctx["internal_latency_total"] = len(rows)
    ctx["internal_latency_ok"] = len(ok_rows)
    ctx["internal_latency_bad"] = len(rows) - len(ok_rows)
    ctx["internal_latency_slowest_ms"] = slowest_ms
    ctx["internal_latency_slowest_name"] = slowest_name
    ctx["internal_latency_state"] = state

    # Hide the separate CA section in the template if it still exists.
    ctx["ca_dns_rows"] = []
    ctx["ca_dns_total"] = 0
    ctx["ca_dns_ok"] = 0
    ctx["ca_dns_bad"] = 0

    return ctx


# --- DNS dashboard add-on: grouped response-time table ---
_dns_dashboard_context_before_response_time_group = dns_dashboard_context


def _rt_state(status: str, ms_value: object) -> str:
    if status != "OK":
        return "bad"

    try:
        ms = float(ms_value)
    except Exception:
        return "unknown"

    if ms >= 250:
        return "bad"
    if ms >= 100:
        return "warn"
    return "good"


def _rt_float(ms_value: object) -> float:
    try:
        return float(ms_value)
    except Exception:
        return 999999.0


def dns_dashboard_context(zone: str | None = None) -> dict[str, Any]:
    ctx = _dns_dashboard_context_before_response_time_group(zone)

    rows = []

    for r in ctx.get("cf_rows", []) or []:
        rows.append({
            "group": "Cloudflare Authoritative",
            "name": r.get("role", ""),
            "server": r.get("server", ""),
            "query": "SOA",
            "status": r.get("status", ""),
            "response_ms": r.get("response_ms", ""),
            "serial": r.get("serial", ""),
            "state": _rt_state(str(r.get("status", "")), r.get("response_ms")),
            "note": "External authoritative secondary",
            "_sort": (10, _rt_float(r.get("response_ms"))),
        })

    for r in ctx.get("internal_latency_rows", []) or []:
        rows.append({
            "group": "Internal DNS",
            "name": r.get("role", ""),
            "server": r.get("server", ""),
            "query": "SOA",
            "status": r.get("status", ""),
            "response_ms": r.get("response_ms", ""),
            "serial": r.get("serial", ""),
            "state": _rt_state(str(r.get("status", "")), r.get("response_ms")),
            "note": "Direct from raccoon",
            "_sort": (20, _rt_float(r.get("response_ms"))),
        })

    for r in ctx.get("public_rows", []) or []:
        rows.append({
            "group": "Public Resolver",
            "name": r.get("resolver", ""),
            "server": r.get("server", ""),
            "query": "SOA",
            "status": r.get("soa_status", ""),
            "response_ms": r.get("soa_ms", ""),
            "serial": r.get("soa_serial", ""),
            "state": _rt_state(str(r.get("soa_status", "")), r.get("soa_ms")),
            "note": "Recursive SOA",
            "_sort": (30, _rt_float(r.get("soa_ms"))),
        })

        rows.append({
            "group": "Public Resolver",
            "name": r.get("resolver", ""),
            "server": r.get("server", ""),
            "query": "NS",
            "status": r.get("ns_status", ""),
            "response_ms": r.get("ns_ms", ""),
            "serial": "",
            "state": _rt_state(str(r.get("ns_status", "")), r.get("ns_ms")),
            "note": "Recursive NS",
            "_sort": (31, _rt_float(r.get("ns_ms"))),
        })

    rows = sorted(rows, key=lambda x: x.get("_sort", (99, 999999.0)))

    for r in rows:
        r.pop("_sort", None)

    ok = sum(1 for r in rows if r.get("status") == "OK")
    bad = len(rows) - ok

    slowest = None
    for r in rows:
        if r.get("status") != "OK":
            continue
        try:
            ms = float(r.get("response_ms"))
        except Exception:
            continue
        if slowest is None or ms > slowest["ms"]:
            slowest = {
                "ms": ms,
                "name": r.get("name") or r.get("server") or "unknown",
                "query": r.get("query") or "",
            }

    ctx["response_time_rows"] = rows
    ctx["response_time_total"] = len(rows)
    ctx["response_time_ok"] = ok
    ctx["response_time_bad"] = bad
    ctx["response_time_slowest_ms"] = round(slowest["ms"], 1) if slowest else ""
    ctx["response_time_slowest_name"] = slowest["name"] if slowest else ""
    ctx["response_time_slowest_query"] = slowest["query"] if slowest else ""

    return ctx


# --- DNS dashboard add-on: clean TV table, no duplicate sections ---
_dns_dashboard_context_before_clean_tv_table = dns_dashboard_context


def _dns_tv_ms(value):
    try:
        return round(float(value), 1)
    except Exception:
        return ""


def _dns_tv_status_state(status, ms_value=None, state_hint=""):
    status = str(status or "")
    hint = str(state_hint or "").lower()

    if status != "OK":
        return "ERROR"

    if hint in ("cached", "behind"):
        return "CACHED"
    if hint in ("mismatch", "diff"):
        return "MISMATCH"
    if hint in ("current", "ok", "expected"):
        return "OK"

    try:
        ms = float(ms_value)
    except Exception:
        return "OK"

    if ms >= 250:
        return "SLOW"
    if ms >= 100:
        return "WARN"
    return "OK"


def _dns_tv_health_value(state):
    if state in ("OK",):
        return "ok"
    if state in ("CACHED", "WARN"):
        return "warn"
    return "bad"


def dns_dashboard_context(zone: str | None = None):
    ctx = _dns_dashboard_context_before_clean_tv_table(zone)

    rows = []

    for r in ctx.get("cf_rows", []) or []:
        state = _dns_tv_status_state(r.get("status"), r.get("response_ms"), r.get("sync"))
        rows.append({
            "area": "Cloudflare",
            "check": r.get("role", ""),
            "server": r.get("server", ""),
            "query": "SOA",
            "status": r.get("status", ""),
            "response_ms": _dns_tv_ms(r.get("response_ms")),
            "serial_or_result": r.get("serial", ""),
            "state": state,
            "note": "External authoritative secondary",
            "health": _dns_tv_health_value(state),
            "_sort": (10, _dns_tv_ms(r.get("response_ms")) or 999999),
        })

    for r in ctx.get("internal_latency_rows", []) or []:
        state = _dns_tv_status_state(r.get("status"), r.get("response_ms"), "ok")
        rows.append({
            "area": "Internal DNS",
            "check": r.get("role", ""),
            "server": r.get("server", ""),
            "query": "SOA",
            "status": r.get("status", ""),
            "response_ms": _dns_tv_ms(r.get("response_ms")),
            "serial_or_result": r.get("serial", ""),
            "state": state,
            "note": "Direct query from raccoon",
            "health": _dns_tv_health_value(state),
            "_sort": (20, _dns_tv_ms(r.get("response_ms")) or 999999),
        })

    for r in ctx.get("public_rows", []) or []:
        state = _dns_tv_status_state(r.get("soa_status"), r.get("soa_ms"), r.get("sync"))
        rows.append({
            "area": "Public Resolver",
            "check": r.get("resolver", ""),
            "server": r.get("server", ""),
            "query": "SOA",
            "status": r.get("soa_status", ""),
            "response_ms": _dns_tv_ms(r.get("soa_ms")),
            "serial_or_result": r.get("soa_serial", ""),
            "state": state,
            "note": "Recursive cache; older serial can be normal",
            "health": _dns_tv_health_value(state),
            "_sort": (30, _dns_tv_ms(r.get("soa_ms")) or 999999),
        })

    for r in ctx.get("ns_rows", []) or []:
        raw_check = str(r.get("check", ""))
        normalized = raw_check.upper()

        if normalized in ("EXPECTED", "OK"):
            state = "OK"
        elif normalized in ("DIFF", "MISMATCH"):
            state = "MISMATCH"
        elif normalized == "ERROR":
            state = "ERROR"
        else:
            state = _dns_tv_status_state(r.get("status"), r.get("response_ms"), raw_check)

        result = raw_check
        if not result:
            result = r.get("ns_values", "")

        rows.append({
            "area": "Public Resolver",
            "check": r.get("resolver", ""),
            "server": r.get("server", ""),
            "query": "NS",
            "status": r.get("status", ""),
            "response_ms": _dns_tv_ms(r.get("response_ms")),
            "serial_or_result": result,
            "state": state,
            "note": "Expected Cloudflare NS pair",
            "health": _dns_tv_health_value(state),
            "_sort": (40, _dns_tv_ms(r.get("response_ms")) or 999999),
        })

    rows = sorted(rows, key=lambda x: x.get("_sort", (99, 999999)))
    for r in rows:
        r.pop("_sort", None)

    ok_count = sum(1 for r in rows if r.get("health") == "ok")
    warn_count = sum(1 for r in rows if r.get("health") == "warn")
    bad_count = sum(1 for r in rows if r.get("health") == "bad")

    ctx["dashboard_check_rows"] = rows
    ctx["dashboard_check_total"] = len(rows)
    ctx["dashboard_check_ok"] = ok_count
    ctx["dashboard_check_warn"] = warn_count
    ctx["dashboard_check_bad"] = bad_count

    return ctx

