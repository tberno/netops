import html
import socket
from typing import Any
from urllib.parse import urlencode

from app.core.db import fetch_all


def h(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def safe_float(value: Any) -> float:
    try:
        return float(value or 0)
    except Exception:
        return 0.0


def fmt_speed(value: Any) -> str:
    bps = safe_float(value)
    if bps <= 0:
        return ""

    units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]
    idx = 0

    while bps >= 1000 and idx < len(units) - 1:
        bps /= 1000
        idx += 1

    if bps >= 100:
        num = f"{bps:.0f}"
    elif bps >= 10:
        num = f"{bps:.1f}".rstrip("0").rstrip(".")
    else:
        num = f"{bps:.2f}".rstrip("0").rstrip(".")

    return f"{num} {units[idx]}"


def fmt_rate(octets_per_second: Any) -> str:
    return fmt_speed(safe_float(octets_per_second) * 8)


def selected_device_ids(device_ids: str = "") -> list[int]:
    ids: list[int] = []
    for part in str(device_ids or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            did = int(part)
        except Exception:
            continue
        if did not in ids:
            ids.append(did)
    return ids


def ids_csv(ids: list[int]) -> str:
    return ",".join(str(x) for x in ids)


def looks_like_ip(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False

    try:
        socket.inet_pton(socket.AF_INET, text)
        return True
    except Exception:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, text)
        return True
    except Exception:
        return False


def device_label(row: dict[str, Any]) -> str:
    for key in ("sysName", "hostname", "device", "ip_addr"):
        value = row.get(key)
        if value and not (key == "sysName" and looks_like_ip(value)):
            return str(value)
    return str(row.get("device_id") or "")


def valid_picker_name(name: str) -> bool:
    text = str(name or "").strip()
    if not text:
        return False
    if set(text) <= {"-", "_", ".", " "}:
        return False
    if text.lower() in {"none", "null", "unknown", "localhost"}:
        return False
    return True


def make_report_url(prefix: str, q: str, limit: int, ids: list[int]) -> str:
    params = {}
    if q:
        params["q"] = q
    if limit != 150:
        params["limit"] = str(limit)
    if ids:
        params["device_ids"] = ids_csv(ids)

    path = f"{prefix}/reports/interface-statistics"
    if not params:
        return path
    return path + "?" + urlencode(params)


def device_catalog() -> list[dict[str, Any]]:
    rows = fetch_all("""
        SELECT
            device_id,
            hostname,
            sysName,
            INET6_NTOA(ip) AS ip_addr,
            os,
            hardware,
            status
        FROM devices
        ORDER BY COALESCE(NULLIF(sysName,''), NULLIF(hostname,''), INET6_NTOA(ip))
    """)

    out = []
    seen = set()

    for row in rows:
        try:
            did = int(row.get("device_id"))
        except Exception:
            continue

        name = device_label(row).strip()
        if not valid_picker_name(name):
            continue

        key = name.lower()
        if key in seen:
            continue
        seen.add(key)

        out.append({"id": did, "name": name})

    return out


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


def status_badge(value: Any) -> str:
    raw = str(value or "").strip().lower()

    if raw in {"up", "ok", "online", "active", "1"}:
        return '<span class="badge up">up</span>'
    if raw in {"down", "critical", "offline", "failed", "0"}:
        return '<span class="badge down">down</span>'
    return f'<span class="badge warn">{h(raw or "unknown")}</span>'


def device_anchor(prefix: str, row: dict[str, Any]) -> str:
    did = row.get("device_id")
    label = row.get("device") or device_label(row)
    if did:
        return f'<a href="{prefix}/device/{h(did)}">{h(label)}</a>'
    return h(label)


def interface_anchor(prefix: str, row: dict[str, Any]) -> str:
    label = row.get("ifName") or row.get("ifDescr") or row.get("ifIndex") or ""
    port_id = row.get("port_id")
    if port_id:
        return f'<a href="{prefix}/interface/{h(port_id)}">{h(label)}</a>'
    return h(label)


def interface_statistics_context(prefix: str, q: str = "", device_ids: str = "", limit: int = 150):
    q = (q or "").strip()

    try:
        limit = int(limit)
    except Exception:
        limit = 150
    limit = max(1, min(limit, 2000))

    selected_ids = selected_device_ids(device_ids)

    where_parts = []
    params: list[Any] = []

    if selected_ids:
        where_parts.append("d.device_id IN (" + ",".join(["%s"] * len(selected_ids)) + ")")
        params.extend(selected_ids)

    if q:
        where_parts.append("(d.hostname LIKE %s OR d.sysName LIKE %s OR p.ifName LIKE %s OR p.ifAlias LIKE %s OR p.ifDescr LIKE %s)")
        params.extend([f"%{q}%"] * 5)

    where = "WHERE " + " AND ".join(where_parts) if where_parts else ""
    params.append(limit)

    raw_rows = fetch_all(f"""
        SELECT
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)) AS device,
            d.device_id,
            p.*,
            COALESCE(f.mac_count, 0) AS mac_count
        FROM ports p
        JOIN devices d ON d.device_id = p.device_id
        LEFT JOIN (
            SELECT port_id, COUNT(*) AS mac_count
            FROM ports_fdb
            GROUP BY port_id
        ) f ON f.port_id = p.port_id
        {where}
        ORDER BY COALESCE(p.ifInOctets_rate,0) + COALESCE(p.ifOutOctets_rate,0) DESC
        LIMIT %s
    """, tuple(params))

    rows = []
    for row in raw_rows:
        rows.append({
            "device": device_anchor(prefix, row),
            "interface": interface_anchor(prefix, row),
            "status": status_badge(row.get("ifOperStatus")),
            "speed": fmt_speed(row.get("ifSpeed")),
            "macs": row.get("mac_count") or 0,
            "tx": fmt_rate(row.get("ifOutOctets_rate")),
            "rx": fmt_rate(row.get("ifInOctets_rate")),
            "tx_errors": row.get("ifOutErrors_rate") or 0,
            "rx_errors": row.get("ifInErrors_rate") or 0,
            "title": row.get("ifAlias") or "",
        })

    selected_devices, available_devices = switch_picker_context(prefix, selected_ids, q, limit)

    columns = [
        {"key": "device", "label": "Device", "html": True},
        {"key": "interface", "label": "Interface", "html": True},
        {"key": "status", "label": "Status", "html": True},
        {"key": "speed", "label": "Speed"},
        {"key": "macs", "label": "MACs"},
        {"key": "tx", "label": "Tx Bits/Sec"},
        {"key": "rx", "label": "Rx Bits/Sec"},
        {"key": "tx_errors", "label": "Tx Errors"},
        {"key": "rx_errors", "label": "Rx Errors"},
        {"key": "title", "label": "Title"},
    ]

    return {
        "title": "Interface Statistics",
        "subtitle": f"Top {len(rows)} interfaces by traffic",
        "q": q,
        "limit": limit,
        "columns": columns,
        "rows": rows,
        "selected_devices": selected_devices,
        "available_devices": available_devices,
        "selected_ids_csv": ids_csv(selected_ids),
        "clear_url": make_report_url(prefix, "", limit, selected_ids),
        "reset_url": f"{prefix}/reports/interface-statistics",
        "clear_selected_url": f"{prefix}/reports/interface-statistics",
        "export_url": make_report_url(prefix, q, limit, selected_ids).replace("/reports/interface-statistics", "/reports/interface-statistics.csv", 1),
        "limit_options": [50, 100, 150, 250, 500, 1000, 2000],
    }
