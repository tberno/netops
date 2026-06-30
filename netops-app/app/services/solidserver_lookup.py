import base64
import json
import os
import ssl
import urllib.parse
import urllib.request
from typing import Any

from app.services.interface_stats import h


def cfg() -> dict[str, str]:
    return {
        "base": (os.getenv("EIP_BASE_URL") or os.getenv("SOLIDSERVER_URL") or "").rstrip("/"),
        "user": os.getenv("EIP_USER") or os.getenv("SOLIDSERVER_USER") or "",
        "pass": os.getenv("EIP_PASS") or os.getenv("SOLIDSERVER_PASS") or "",
    }


def eip_quote(value: str) -> str:
    text = str(value or "").replace("\\", "\\\\").replace("'", "\\'")
    return "'" + text + "'"


def eip_like(value: str) -> str:
    return eip_quote("%" + str(value or "") + "%")


def clean_mac(value: str) -> str:
    return str(value or "").lower().replace(":", "").replace("-", "").replace(".", "").strip()


def eip_mac_like(value: str) -> str:
    raw = clean_mac(value)
    if not raw:
        raw = value
    return eip_like(raw)


def auth_header(user: str, password: str) -> str:
    raw = f"{user}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def decode_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]

    if not isinstance(payload, dict):
        return []

    for key in ("data", "result", "rows", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]

    # EfficientIP sometimes returns dict-of-id rows.
    out = []
    for value in payload.values():
        if isinstance(value, dict):
            out.append(value)
    return out


def eip_fetch(endpoint: str, where: str, max_rows: int = 50) -> list[dict[str, Any]]:
    c = cfg()

    if not c["base"] or not c["user"] or not c["pass"]:
        raise RuntimeError("missing EIP_BASE_URL/EIP_USER/EIP_PASS")

    endpoint = "/" + endpoint.strip("/")
    url = c["base"] + endpoint

    params = {
        "WHERE": where,
        "limit": str(max_rows),
    }

    headers = {
        "Authorization": auth_header(c["user"], c["pass"]),
        "Accept": "application/json",
    }

    ctx = ssl._create_unverified_context()

    # Try GET first.
    get_url = url + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(get_url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
            body = resp.read().decode("utf-8", "replace")
            return decode_rows(json.loads(body))
    except Exception:
        pass

    # Fallback to POST form.
    data = urllib.parse.urlencode(params).encode("utf-8")
    post_headers = dict(headers)
    post_headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=data, headers=post_headers, method="POST")

    with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
        body = resp.read().decode("utf-8", "replace")
        return decode_rows(json.loads(body))


def dedupe(rows: list[dict[str, Any]], keys: list[str], limit: int) -> list[dict[str, Any]]:
    seen = set()
    out = []

    for row in rows:
        ident = tuple(str(row.get(k) or "") for k in keys)

        if ident in seen:
            continue

        seen.add(ident)
        out.append(row)

        if len(out) >= limit:
            break

    return out


def section(title: str, columns: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "title": title,
        "columns": columns,
        "rows": rows,
    }


def error_section(exc: Exception) -> dict[str, Any]:
    return {
        "title": "SOLIDserver lookup error",
        "columns": [
            {"key": "source", "label": "Source"},
            {"key": "error", "label": "Error"},
        ],
        "rows": [
            {"source": "SOLIDserver", "error": str(exc)}
        ],
        "is_error": True,
    }


def solidserver_lookup_sections(q: str, limit: int = 50) -> list[dict[str, Any]]:
    q = (q or "").strip()

    if not q:
        return []

    limit = max(1, min(int(limit or 50), 100))

    exact = eip_quote(q)
    like = eip_like(q)
    mac_like = eip_mac_like(q)
    is_ip = looks_ip(q)

    def addr_tests(field: str) -> list[str]:
        if is_ip:
            return [f"{field}={exact}"]
        return []

    sections: list[dict[str, Any]] = []

    try:
        ipam_where = " OR ".join([
            *addr_tests("hostaddr"),
            f"name LIKE {like}",
            f"ip_alias LIKE {like}",
            f"mac_addr LIKE {mac_like}",
            f"subnet_name LIKE {like}",
            f"pool_name LIKE {like}",
        ])

        dhcp_static_where = " OR ".join([
            *addr_tests("dhcphost_addr"),
            f"dhcphost_name LIKE {like}",
            f"dhcphost_mac_addr LIKE {mac_like}",
            f"db_hostname LIKE {like}",
            f"dhcpscope_name LIKE {like}",
            f"dhcpsn_name LIKE {like}",
        ])

        dns_rr_where = " OR ".join([
            f"dnsrr_full_name LIKE {like}",
            f"dnsrr_name LIKE {like}",
            f"dnsrr_value LIKE {like}",
            f"dnszone_name LIKE {like}",
        ])

        dns_zone_where = " OR ".join([
            f"dnszone_name LIKE {like}",
        ])

        dhcp_scope_where = " OR ".join([
            f"dhcpscope_name LIKE {like}",
            *addr_tests("dhcpscope_net_addr"),
            f"dhcpsn_name LIKE {like}",
            f"dhcp_name LIKE {like}",
        ])

        dhcp_range_where = " OR ".join([
            f"dhcpsn_name LIKE {like}",
            f"dhcpscope_name LIKE {like}",
            f"dhcprange_name LIKE {like}",
            *addr_tests("dhcprange_start_addr"),
            *addr_tests("dhcprange_end_addr"),
            f"dhcp_name LIKE {like}",
        ])

        ipam = dedupe(
            eip_fetch("/rest/ip_address_list", ipam_where, limit),
            ["hostaddr", "name", "mac_addr"],
            limit,
        )

        statics = dedupe(
            eip_fetch("/rest/dhcp_static_list", dhcp_static_where, limit),
            ["dhcphost_addr", "dhcphost_name", "dhcphost_mac_addr"],
            limit,
        )

        rrs = dedupe(
            eip_fetch("/rest/dns_rr_list", dns_rr_where, limit),
            ["dnsrr_full_name", "dnsrr_type", "dnsrr_value"],
            limit,
        )

        zones = dedupe(
            eip_fetch("/rest/dns_zone_list", dns_zone_where, limit),
            ["dnszone_name"],
            limit,
        )

        scopes = dedupe(
            eip_fetch("/rest/dhcp_scope_list", dhcp_scope_where, limit),
            ["dhcpscope_name", "dhcpscope_net_addr", "dhcpsn_name"],
            limit,
        )

        ranges = dedupe(
            eip_fetch("/rest/dhcp_range_list", dhcp_range_where, limit),
            ["dhcprange_start_addr", "dhcprange_end_addr", "dhcpscope_name"],
            limit,
        )

        if ipam:
            rows = []
            for r in ipam:
                rows.append({
                    "ip": r.get("hostaddr") or "",
                    "name": r.get("name") or r.get("db_hostname") or "",
                    "alias": r.get("ip_alias") or "",
                    "mac": r.get("mac_addr") or "",
                    "subnet": r.get("subnet_name") or "",
                    "pool": r.get("pool_name") or "",
                    "updated": r.get("trace_last_update_date") or "",
                })

            sections.append(section("SOLIDserver IPAM", [
                {"key": "ip", "label": "IP"},
                {"key": "name", "label": "Name"},
                {"key": "alias", "label": "Alias"},
                {"key": "mac", "label": "MAC"},
                {"key": "subnet", "label": "Subnet"},
                {"key": "pool", "label": "Pool"},
                {"key": "updated", "label": "Updated"},
            ], rows))

        if statics:
            rows = []
            for r in statics:
                rows.append({
                    "name": r.get("dhcphost_name") or "",
                    "ip": r.get("dhcphost_addr") or "",
                    "mac": r.get("dhcphost_mac_addr") or "",
                    "db_hostname": r.get("db_hostname") or "",
                    "scope": r.get("dhcpscope_name") or "",
                    "shared": r.get("dhcpsn_name") or "",
                    "server": r.get("dhcp_name") or "",
                    "last_seen": r.get("dhcphost_last_seen") or "",
                })

            sections.append(section("SOLIDserver DHCP Static / Reservations", [
                {"key": "name", "label": "Name"},
                {"key": "ip", "label": "IP"},
                {"key": "mac", "label": "MAC"},
                {"key": "db_hostname", "label": "DB Hostname"},
                {"key": "scope", "label": "Scope"},
                {"key": "shared", "label": "Shared Network"},
                {"key": "server", "label": "DHCP Server"},
                {"key": "last_seen", "label": "Last Seen"},
            ], rows))

        if rrs:
            rows = []
            for r in rrs:
                rows.append({
                    "name": r.get("dnsrr_full_name") or r.get("dnsrr_name") or "",
                    "type": r.get("dnsrr_type") or "",
                    "value": r.get("dnsrr_value") or r.get("dnsrr_data") or "",
                    "zone": r.get("dnszone_name") or "",
                    "ttl": r.get("dnsrr_ttl") or "",
                    "updated": r.get("trace_last_update_date") or "",
                })

            sections.append(section("SOLIDserver DNS Records", [
                {"key": "name", "label": "Name"},
                {"key": "type", "label": "Type"},
                {"key": "value", "label": "Value"},
                {"key": "zone", "label": "Zone"},
                {"key": "ttl", "label": "TTL"},
                {"key": "updated", "label": "Updated"},
            ], rows))

        if zones:
            rows = []
            for r in zones:
                rows.append({
                    "zone": r.get("dnszone_name") or "",
                    "view": r.get("dnsview_name") or "",
                    "type": r.get("dnszone_type") or "",
                    "server": r.get("dns_name") or "",
                    "updated": r.get("trace_last_update_date") or "",
                })

            sections.append(section("SOLIDserver DNS Zones", [
                {"key": "zone", "label": "Zone"},
                {"key": "view", "label": "View"},
                {"key": "type", "label": "Type"},
                {"key": "server", "label": "Server"},
                {"key": "updated", "label": "Updated"},
            ], rows))

        if scopes:
            rows = []
            for r in scopes:
                rows.append({
                    "shared": r.get("dhcpsn_name") or "",
                    "scope": r.get("dhcpscope_name") or "",
                    "network": r.get("dhcpscope_net_addr") or "",
                    "prefix": r.get("dhcpscope_prefix") or "",
                    "server": r.get("dhcp_name") or "",
                    "failover": r.get("dhcpfailover_name") or "",
                })

            sections.append(section("SOLIDserver DHCP Scopes", [
                {"key": "shared", "label": "Shared Network"},
                {"key": "scope", "label": "Scope"},
                {"key": "network", "label": "Network"},
                {"key": "prefix", "label": "Prefix"},
                {"key": "server", "label": "DHCP Server"},
                {"key": "failover", "label": "Failover"},
            ], rows))

        if ranges:
            rows = []
            for r in ranges:
                rows.append({
                    "shared": r.get("dhcpsn_name") or "",
                    "scope": r.get("dhcpscope_name") or "",
                    "range": r.get("dhcprange_name") or "",
                    "start": r.get("dhcprange_start_addr") or "",
                    "end": r.get("dhcprange_end_addr") or "",
                    "used": r.get("dhcprange_lease_count") or "",
                    "size": r.get("dhcprange_size") or "",
                    "pct": r.get("dhcprange_lease_percent") or "",
                    "server": r.get("dhcp_name") or "",
                })

            sections.append(section("SOLIDserver DHCP Ranges", [
                {"key": "shared", "label": "Shared Network"},
                {"key": "scope", "label": "Scope"},
                {"key": "range", "label": "Range"},
                {"key": "start", "label": "Start"},
                {"key": "end", "label": "End"},
                {"key": "used", "label": "Used"},
                {"key": "size", "label": "Size"},
                {"key": "pct", "label": "Used %"},
                {"key": "server", "label": "DHCP Server"},
            ], rows))

    except Exception as exc:
        sections.append(error_section(exc))

    return sections
