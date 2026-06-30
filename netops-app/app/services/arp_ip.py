from typing import Any
from urllib.parse import urlencode

from app.core.db import fetch_all
from app.services.interface_stats import (
    device_catalog,
    h,
    ids_csv,
    selected_device_ids,
)


def table_columns(table: str) -> set[str]:
    try:
        rows = fetch_all(f"SHOW COLUMNS FROM {table}")
        return {str(r.get("Field")) for r in rows if r.get("Field")}
    except Exception:
        return set()


def make_report_url(prefix: str, q: str, limit: int, ids: list[int]) -> str:
    params = {}

    if q:
        params["q"] = q

    if limit != 500:
        params["limit"] = str(limit)

    if ids:
        params["device_ids"] = ids_csv(ids)

    path = f"{prefix}/reports/arp-ip"

    if not params:
        return path

    return path + "?" + urlencode(params)


def switch_picker_context(prefix: str, selected_ids: list[int], q: str, limit: int):
    selected_set = set(selected_ids)
    selected = []
    available = []

    for item in device_catalog():
        did = item["id"]
        name = item["name"]

        if did in selected_set:
            next_ids = [x for x in selected_ids if x != did]
            selected.append({
                "id": did,
                "name": name,
                "href": make_report_url(prefix, q, limit, next_ids),
            })
        else:
            next_ids = list(selected_ids)
            if did not in next_ids:
                next_ids.append(did)

            available.append({
                "id": did,
                "name": name,
                "href": make_report_url(prefix, q, limit, next_ids),
            })

    selected.sort(key=lambda x: x["name"].lower())
    available.sort(key=lambda x: x["name"].lower())

    return selected, available


def clean_mac(value: Any) -> str:
    text = str(value or "").strip()

    if not text:
        return ""

    raw = text.lower().replace(":", "").replace("-", "").replace(".", "")

    if len(raw) == 12:
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))

    return text


def clean_query_mac(value: str) -> str:
    return str(value or "").lower().replace(":", "").replace("-", "").replace(".", "").strip()


def norm_sql(expr: str) -> str:
    return f"LOWER(REPLACE(REPLACE(REPLACE(CAST({expr} AS CHAR), ':', ''), '-', ''), '.', ''))"


def device_anchor(prefix: str, row: dict[str, Any]) -> str:
    did = row.get("device_id")
    label = row.get("device") or row.get("hostname") or row.get("device_id") or ""

    if did:
        return f'<a href="{prefix}/device/{h(did)}">{h(label)}</a>'

    return h(label)


def interface_anchor(prefix: str, row: dict[str, Any]) -> str:
    port_id = row.get("port_id")
    label = row.get("ifName") or row.get("ifDescr") or row.get("ifIndex") or ""

    if port_id:
        return f'<a href="{prefix}/interface/{h(port_id)}">{h(label)}</a>'

    return h(label)


def arp_ip_context(prefix: str, q: str = "", device_ids: str = "", limit: int = 500):
    q = (q or "").strip()

    try:
        limit = int(limit)
    except Exception:
        limit = 500

    limit = max(1, min(limit, 10000))
    selected_ids = selected_device_ids(device_ids)

    ip_cols = table_columns("ipv4_addresses")
    mac_cols = table_columns("ipv4_mac")

    required = {"ipv4_address", "port_id"}
    missing = sorted(required - ip_cols)

    selected_devices, available_devices = switch_picker_context(prefix, selected_ids, q, limit)

    if missing:
        return {
            "title": "ARP / IP",
            "subtitle": "LibreNMS ipv4_addresses schema mismatch",
            "q": q,
            "limit": limit,
            "columns": [{"key": "error", "label": "Error"}],
            "rows": [{"error": "Missing columns in ipv4_addresses: " + ", ".join(missing)}],
            "selected_devices": selected_devices,
            "available_devices": available_devices,
            "selected_ids_csv": ids_csv(selected_ids),
            "clear_url": make_report_url(prefix, "", limit, selected_ids),
            "clear_selected_url": f"{prefix}/reports/arp-ip",
            "reset_url": f"{prefix}/reports/arp-ip",
            "export_url": make_report_url(prefix, q, limit, selected_ids).replace("/reports/arp-ip", "/reports/arp-ip.csv", 1),
            "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
        }

    prefix_select = "ia.ipv4_prefixlen AS prefix_len" if "ipv4_prefixlen" in ip_cols else "NULL AS prefix_len"
    context_select = "ia.context_name AS context_name" if "context_name" in ip_cols else "NULL AS context_name"

    joins = []
    select_mac = "NULL AS mac"

    if (
        "ipv4_address_id" in ip_cols
        and "ipv4_address_id" in mac_cols
        and "mac_address" in mac_cols
    ):
        joins.append("""
        LEFT JOIN ipv4_mac im ON im.ipv4_address_id = ia.ipv4_address_id
        """)
        select_mac = "im.mac_address AS mac"

    where_parts = []
    params: list[Any] = []

    if selected_ids:
        where_parts.append("d.device_id IN (" + ",".join(["%s"] * len(selected_ids)) + ")")
        params.extend(selected_ids)

    if q:
        like_parts = [
            "d.hostname LIKE %s",
            "d.sysName LIKE %s",
            "p.ifName LIKE %s",
            "p.ifAlias LIKE %s",
            "p.ifDescr LIKE %s",
            "CAST(ia.ipv4_address AS CHAR) LIKE %s",
        ]
        params.extend([f"%{q}%"] * 6)

        if select_mac != "NULL AS mac":
            like_parts.append("im.mac_address LIKE %s")
            like_parts.append(f"{norm_sql('im.mac_address')} LIKE %s")
            params.append(f"%{q}%")
            params.append(f"%{clean_query_mac(q)}%")

        where_parts.append("(" + " OR ".join(like_parts) + ")")

    where = "WHERE " + " AND ".join(where_parts) if where_parts else ""

    params.append(limit)

    raw_rows = fetch_all(f"""
        SELECT
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)) AS device,
            d.hostname,
            d.device_id,
            p.port_id,
            p.ifIndex,
            p.ifName,
            p.ifDescr,
            p.ifAlias,
            ia.ipv4_address AS ip_addr,
            {prefix_select},
            {context_select},
            {select_mac}
        FROM ipv4_addresses ia
        JOIN ports p ON p.port_id = ia.port_id
        JOIN devices d ON d.device_id = p.device_id
        {' '.join(joins)}
        {where}
        ORDER BY
            INET_ATON(ia.ipv4_address),
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)),
            p.ifIndex
        LIMIT %s
    """, tuple(params))

    rows = []
    for row in raw_rows:
        prefix_len = row.get("prefix_len")
        ip_addr = row.get("ip_addr") or ""

        if prefix_len not in (None, ""):
            cidr = f"{ip_addr}/{prefix_len}"
        else:
            cidr = ip_addr

        rows.append({
            "device": device_anchor(prefix, row),
            "interface": interface_anchor(prefix, row),
            "ip": cidr,
            "mac": clean_mac(row.get("mac")),
            "context": row.get("context_name") or "",
            "ifindex": row.get("ifIndex") or "",
            "descr": row.get("ifDescr") or "",
            "title": row.get("ifAlias") or "",
        })

    columns = [
        {"key": "device", "label": "Device", "html": True},
        {"key": "interface", "label": "Interface", "html": True},
        {"key": "ip", "label": "IP / Prefix"},
        {"key": "mac", "label": "MAC"},
        {"key": "context", "label": "Context"},
        {"key": "ifindex", "label": "IfIndex"},
        {"key": "descr", "label": "Description"},
        {"key": "title", "label": "Title"},
    ]

    return {
        "title": "ARP / IP",
        "subtitle": f"Showing {len(rows)} IP entries",
        "q": q,
        "limit": limit,
        "columns": columns,
        "rows": rows,
        "selected_devices": selected_devices,
        "available_devices": available_devices,
        "selected_ids_csv": ids_csv(selected_ids),
        "clear_url": make_report_url(prefix, "", limit, selected_ids),
        "clear_selected_url": f"{prefix}/reports/arp-ip",
        "reset_url": f"{prefix}/reports/arp-ip",
        "export_url": make_report_url(prefix, q, limit, selected_ids).replace(
            "/reports/arp-ip",
            "/reports/arp-ip.csv",
            1,
        ),
        "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
    }
