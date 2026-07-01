import os
import random
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Any

from app.services.ntp_dashboard import _ntp_query, _fmt_ms


DNS_QTYPE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
}

DNS_QTYPE_NAME = {v: k for k, v in DNS_QTYPE.items()}


DEFAULT_NTP_TARGETS = [
    "time.middlebury.edu",
    "zeus.middlebury.edu",
    "time.cloudflare.com",
    "time.google.com",
    "time.aws.com",
    "time.nist.gov",
]

DEFAULT_DNS_QUERIES = [
    "time.middlebury.edu",
    "zeus.middlebury.edu",
    "www.middlebury.edu",
]

DEFAULT_RESOLVERS = [
    {"name": "Middlebury DNS 1", "server": "140.233.1.4", "role": "middlebury"},
    {"name": "Middlebury DNS 2 / SolidServer", "server": "140.233.2.204", "role": "middlebury"},
    {"name": "Cloudflare DNS", "server": "1.1.1.1", "role": "reference"},
    {"name": "Google DNS", "server": "8.8.8.8", "role": "reference"},
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _split_csv_env(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    return [x.strip() for x in raw.split(",") if x.strip()]


def _dns_resolvers() -> list[dict[str, str]]:
    raw = os.getenv("TIME_DNS_RESOLVERS", "").strip()
    if not raw:
        return DEFAULT_RESOLVERS

    resolvers = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue

        # Format:
        # Name=IP=role
        parts = [p.strip() for p in item.split("=")]
        if len(parts) == 1:
            resolvers.append({"name": parts[0], "server": parts[0], "role": "reference"})
        elif len(parts) == 2:
            resolvers.append({"name": parts[0], "server": parts[1], "role": "reference"})
        else:
            resolvers.append({"name": parts[0], "server": parts[1], "role": parts[2]})

    return resolvers


def _status_from_latency(latency_ms: float | None, ok: bool) -> tuple[str, str]:
    if not ok or latency_ms is None:
        return "critical", "CRITICAL"
    if latency_ms <= 100:
        return "good", "OK"
    if latency_ms <= 250:
        return "warn", "WARN"
    return "critical", "CRITICAL"


def _encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    out = bytearray()
    for label in name.split("."):
        data = label.encode("ascii")
        out.append(len(data))
        out.extend(data)
    out.append(0)
    return bytes(out)


def _decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    original_offset = offset
    seen = set()

    while True:
        if offset >= len(packet):
            raise ValueError("DNS name decode exceeded packet length")

        length = packet[offset]

        if length == 0:
            offset += 1
            break

        # Compression pointer.
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Bad DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise ValueError("DNS compression pointer loop")
            seen.add(pointer)
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        offset += 1
        labels.append(packet[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), (original_offset if jumped else offset)


def _parse_answers(packet: bytes, ancount: int, offset: int) -> tuple[list[str], list[str], int]:
    records: list[str] = []
    cnames: list[str] = []

    for _ in range(ancount):
        name, offset = _decode_name(packet, offset)

        if offset + 10 > len(packet):
            raise ValueError("Short DNS answer")

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10

        rdata_offset = offset
        rdata = packet[offset:offset + rdlength]
        offset += rdlength

        if rtype == DNS_QTYPE["A"] and rdlength == 4:
            value = socket.inet_ntoa(rdata)
            records.append(f"{name} A {value}")
        elif rtype == DNS_QTYPE["CNAME"]:
            cname, _ = _decode_name(packet, rdata_offset)
            cnames.append(cname)
            records.append(f"{name} CNAME {cname}")
        elif rtype == DNS_QTYPE["NS"]:
            ns, _ = _decode_name(packet, rdata_offset)
            records.append(f"{name} NS {ns}")
        else:
            rtype_name = DNS_QTYPE_NAME.get(rtype, str(rtype))
            records.append(f"{name} {rtype_name} {rdlength} bytes")

    return records, cnames, offset


def _dns_query(resolver: dict[str, str], qname: str, qtype: str = "A", timeout: float = 1.5) -> dict[str, Any]:
    qtype = qtype.upper()
    qtype_num = DNS_QTYPE.get(qtype, 1)

    result: dict[str, Any] = {
        "resolver_name": resolver["name"],
        "resolver": resolver["server"],
        "role": resolver.get("role", "reference"),
        "role_label": "Middlebury monitored" if resolver.get("role") == "middlebury" else "Third-party reference",
        "query": qname,
        "qtype": qtype,
        "ok": False,
        "state": "critical",
        "status": "CRITICAL",
        "latency_ms": None,
        "rcode": None,
        "answers": [],
        "answer_text": "—",
        "error": "",
        "checked_at": _utc_now(),
    }

    try:
        server_ip = socket.gethostbyname(resolver["server"])
    except Exception as exc:
        result["error"] = f"Resolver DNS failed: {exc}"
        return result

    txid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(qname) + struct.pack("!HH", qtype_num, 1)
    payload = header + question

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            start = time.perf_counter()
            sock.sendto(payload, (server_ip, 53))
            packet, _ = sock.recvfrom(1500)
            elapsed = (time.perf_counter() - start) * 1000

        if len(packet) < 12:
            result["error"] = "Short DNS response"
            return result

        rxid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])

        if rxid != txid:
            result["error"] = "DNS transaction ID mismatch"
            return result

        rcode = flags & 0x000F
        offset = 12

        for _ in range(qdcount):
            _, offset = _decode_name(packet, offset)
            offset += 4

        answers, cnames, offset = _parse_answers(packet, ancount, offset)

        ok = rcode == 0 and len(answers) > 0
        state, status = _status_from_latency(elapsed, ok)

        result.update(
            {
                "ok": ok,
                "state": state,
                "status": status,
                "latency_ms": elapsed,
                "rcode": rcode,
                "answers": answers,
                "answer_text": "; ".join(answers[:4]) if answers else "No answers",
                "error": "" if ok else f"rcode={rcode}, answers={ancount}",
            }
        )
        return result

    except socket.timeout:
        result["error"] = "DNS query timed out on UDP/53"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def _min_max_abs_offset(checks: list[dict[str, Any]]) -> tuple[float | None, float | None]:
    values = [abs(c["offset_ms"]) for c in checks if c.get("offset_ms") is not None]
    if not values:
        return None, None
    return min(values), max(values)


def time_dns_dashboard_context() -> dict[str, Any]:
    ntp_targets = _split_csv_env("TIME_DNS_NTP_TARGETS", DEFAULT_NTP_TARGETS)
    dns_queries = _split_csv_env("TIME_DNS_DNS_QUERIES", DEFAULT_DNS_QUERIES)
    resolvers = _dns_resolvers()

    ntp_checks = [_ntp_query(t) for t in ntp_targets]

    dns_checks = []
    for resolver in resolvers:
        for qname in dns_queries:
            dns_checks.append(_dns_query(resolver, qname, "A"))

    monitored_ntp = [c for c in ntp_checks if c.get("role") == "middlebury"]
    reference_ntp = [c for c in ntp_checks if c.get("role") != "middlebury"]

    monitored_dns = [c for c in dns_checks if c.get("role") == "middlebury"]
    reference_dns = [c for c in dns_checks if c.get("role") != "middlebury"]

    service_checks = monitored_ntp + monitored_dns

    good = sum(1 for c in service_checks if c["state"] == "good")
    warn = sum(1 for c in service_checks if c["state"] == "warn")
    critical = sum(1 for c in service_checks if c["state"] == "critical")

    ref_good = sum(1 for c in reference_ntp + reference_dns if c["state"] == "good")
    ref_warn = sum(1 for c in reference_ntp + reference_dns if c["state"] == "warn")
    ref_critical = sum(1 for c in reference_ntp + reference_dns if c["state"] == "critical")

    if critical:
        overall_state = "critical"
        overall_status = "CRITICAL"
    elif warn:
        overall_state = "warn"
        overall_status = "WARN"
    else:
        overall_state = "good"
        overall_status = "OK"

    ntp_min_offset, ntp_max_offset = _min_max_abs_offset(monitored_ntp)
    ref_min_offset, ref_max_offset = _min_max_abs_offset(reference_ntp)

    dns_latencies = [c["latency_ms"] for c in monitored_dns if c.get("latency_ms") is not None and c["ok"]]
    dns_avg = sum(dns_latencies) / len(dns_latencies) if dns_latencies else None
    dns_max = max(dns_latencies) if dns_latencies else None

    return {
        "title": "Time & DNS Health",
        "summary": {
            "overall_state": overall_state,
            "overall_status": overall_status,
            "good": good,
            "warn": warn,
            "critical": critical,
            "reference_good": ref_good,
            "reference_warn": ref_warn,
            "reference_critical": ref_critical,
            "monitored_total": len(service_checks),
            "reference_total": len(reference_ntp) + len(reference_dns),
            "ntp_max_offset": ntp_max_offset,
            "ntp_min_offset": ntp_min_offset,
            "ref_max_offset": ref_max_offset,
            "dns_avg": dns_avg,
            "dns_max": dns_max,
            "checked_at": _utc_now(),
        },
        "ntp_checks": ntp_checks,
        "monitored_ntp": monitored_ntp,
        "reference_ntp": reference_ntp,
        "dns_checks": dns_checks,
        "monitored_dns": monitored_dns,
        "reference_dns": reference_dns,
        "fmt_ms": _fmt_ms,
    }
