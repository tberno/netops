from typing import Any
from urllib.parse import urlencode

from app.core.db import fetch_all
from app.services.interface_stats import (
    device_catalog,
    fmt_speed,
    h,
    ids_csv,
    selected_device_ids,
    status_badge,
)


def make_report_url(prefix: str, q: str, limit: int, ids: list[int]) -> str:
    params = {}

    if q:
        params["q"] = q

    if limit != 150:
        params["limit"] = str(limit)

    if ids:
        params["device_ids"] = ids_csv(ids)

    path = f"{prefix}/reports/interface-configuration"

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


def clean_mac(value: Any) -> str:
    text = str(value or "").strip()

    if not text:
        return ""

    text = text.replace(":", "").replace("-", "").replace(".", "")

    if len(text) == 12:
        return ":".join(text[i:i + 2] for i in range(0, 12, 2)).lower()

    return str(value or "")


def interface_configuration_context(prefix: str, q: str = "", device_ids: str = "", limit: int = 150):
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
        where_parts.append(
            "("
            "d.hostname LIKE %s OR "
            "d.sysName LIKE %s OR "
            "p.ifName LIKE %s OR "
            "p.ifAlias LIKE %s OR "
            "p.ifDescr LIKE %s OR "
            "p.ifType LIKE %s"
            ")"
        )
        params.extend([f"%{q}%"] * 6)

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
            p.ifAdminStatus,
            p.ifOperStatus,
            p.ifSpeed,
            p.ifMtu,
            p.ifType,
            p.ifPhysAddress
        FROM ports p
        JOIN devices d ON d.device_id = p.device_id
        {where}
        ORDER BY
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)),
            p.ifIndex,
            p.ifName
        LIMIT %s
    """, tuple(params))

    rows = []
    for row in raw_rows:
        rows.append({
            "device": device_anchor(prefix, row),
            "interface": interface_anchor(prefix, row),
            "admin": status_badge(row.get("ifAdminStatus")),
            "oper": status_badge(row.get("ifOperStatus")),
            "speed": fmt_speed(row.get("ifSpeed")),
            "mtu": row.get("ifMtu") or "",
            "type": row.get("ifType") or "",
            "mac": clean_mac(row.get("ifPhysAddress")),
            "descr": row.get("ifDescr") or "",
            "title": row.get("ifAlias") or "",
        })

    selected_devices, available_devices = switch_picker_context(prefix, selected_ids, q, limit)

    columns = [
        {"key": "device", "label": "Device", "html": True},
        {"key": "interface", "label": "Interface", "html": True},
        {"key": "admin", "label": "Admin", "html": True},
        {"key": "oper", "label": "Oper", "html": True},
        {"key": "speed", "label": "Speed"},
        {"key": "mtu", "label": "MTU"},
        {"key": "type", "label": "Type"},
        {"key": "mac", "label": "MAC"},
        {"key": "descr", "label": "Description"},
        {"key": "title", "label": "Title"},
    ]

    return {
        "title": "Interface Configuration",
        "subtitle": f"Showing {len(rows)} interfaces",
        "q": q,
        "limit": limit,
        "columns": columns,
        "rows": rows,
        "selected_devices": selected_devices,
        "available_devices": available_devices,
        "selected_ids_csv": ids_csv(selected_ids),
        "clear_url": make_report_url(prefix, "", limit, selected_ids),
        "reset_url": f"{prefix}/reports/interface-configuration",
        "clear_selected_url": f"{prefix}/reports/interface-configuration",
        "export_url": make_report_url(prefix, q, limit, selected_ids).replace(
            "/reports/interface-configuration",
            "/reports/interface-configuration.csv",
            1,
        ),
        "limit_options": [50, 100, 150, 250, 500, 1000, 2000],
    }
