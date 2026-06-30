from typing import Any
from urllib.parse import urlencode

from app.core.db import fetch_all
from app.services.interface_stats import (
    device_catalog,
    fmt_rate,
    fmt_speed,
    h,
    ids_csv,
    selected_device_ids,
    status_badge,
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

    path = f"{prefix}/reports/unused-interfaces"

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


def unused_interfaces_context(prefix: str, q: str = "", device_ids: str = "", limit: int = 500):
    q = (q or "").strip()

    try:
        limit = int(limit)
    except Exception:
        limit = 500

    limit = max(1, min(limit, 10000))
    selected_ids = selected_device_ids(device_ids)

    port_cols = table_columns("ports")
    selected_devices, available_devices = switch_picker_context(prefix, selected_ids, q, limit)

    required = {"port_id", "device_id", "ifIndex"}
    missing = sorted(required - port_cols)

    if missing:
        return {
            "title": "Unused Interfaces",
            "subtitle": "LibreNMS ports schema mismatch",
            "q": q,
            "limit": limit,
            "columns": [{"key": "error", "label": "Error"}],
            "rows": [{"error": "Missing columns in ports: " + ", ".join(missing)}],
            "selected_devices": selected_devices,
            "available_devices": available_devices,
            "selected_ids_csv": ids_csv(selected_ids),
            "clear_url": make_report_url(prefix, "", limit, selected_ids),
            "clear_selected_url": f"{prefix}/reports/unused-interfaces",
            "reset_url": f"{prefix}/reports/unused-interfaces",
            "export_url": make_report_url(prefix, q, limit, selected_ids).replace(
                "/reports/unused-interfaces",
                "/reports/unused-interfaces.csv",
                1,
            ),
            "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
        }

    def col(name: str, fallback: str = "NULL") -> str:
        return f"p.{name}" if name in port_cols else fallback

    if_name = col("ifName")
    if_descr = col("ifDescr")
    if_alias = col("ifAlias")
    if_admin = col("ifAdminStatus")
    if_oper = col("ifOperStatus")
    if_speed = col("ifSpeed", "0")
    if_type = col("ifType")
    if_mtu = col("ifMtu", "NULL")
    if_last_change = col("ifLastChange", "NULL")
    if_in_rate = col("ifInOctets_rate", "0")
    if_out_rate = col("ifOutOctets_rate", "0")
    if_in_errors = col("ifInErrors_rate", "0")
    if_out_errors = col("ifOutErrors_rate", "0")

    where_parts = []

    params: list[Any] = []

    if selected_ids:
        where_parts.append("d.device_id IN (" + ",".join(["%s"] * len(selected_ids)) + ")")
        params.extend(selected_ids)

    # Likely unused = admin up, oper not up, no learned MACs.
    if "ifAdminStatus" in port_cols:
        where_parts.append("LOWER(COALESCE(p.ifAdminStatus,'')) = 'up'")

    if "ifOperStatus" in port_cols:
        where_parts.append("LOWER(COALESCE(p.ifOperStatus,'')) <> 'up'")

    where_parts.append("COALESCE(f.mac_count, 0) = 0")

    if "ifType" in port_cols:
        where_parts.append(
            "("
            "p.ifType IS NULL OR "
            "("
            "LOCATE('softwareloopback', LOWER(p.ifType)) = 0 AND "
            "LOCATE('propvirtual', LOWER(p.ifType)) = 0 AND "
            "LOCATE('tunnel', LOWER(p.ifType)) = 0"
            ")"
            ")"
        )

    if q:
        like_parts = [
            "d.hostname LIKE %s",
            "d.sysName LIKE %s",
        ]
        params.extend([f"%{q}%"] * 2)

        if "ifName" in port_cols:
            like_parts.append("p.ifName LIKE %s")
            params.append(f"%{q}%")

        if "ifAlias" in port_cols:
            like_parts.append("p.ifAlias LIKE %s")
            params.append(f"%{q}%")

        if "ifDescr" in port_cols:
            like_parts.append("p.ifDescr LIKE %s")
            params.append(f"%{q}%")

        if "ifType" in port_cols:
            like_parts.append("p.ifType LIKE %s")
            params.append(f"%{q}%")

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
            {if_name} AS ifName,
            {if_descr} AS ifDescr,
            {if_alias} AS ifAlias,
            {if_admin} AS ifAdminStatus,
            {if_oper} AS ifOperStatus,
            {if_speed} AS ifSpeed,
            {if_type} AS ifType,
            {if_mtu} AS ifMtu,
            {if_last_change} AS ifLastChange,
            {if_in_rate} AS ifInOctets_rate,
            {if_out_rate} AS ifOutOctets_rate,
            {if_in_errors} AS ifInErrors_rate,
            {if_out_errors} AS ifOutErrors_rate,
            COALESCE(f.mac_count, 0) AS mac_count
        FROM ports p
        JOIN devices d ON d.device_id = p.device_id
        LEFT JOIN (
            SELECT port_id, COUNT(*) AS mac_count
            FROM ports_fdb
            GROUP BY port_id
        ) f ON f.port_id = p.port_id
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
            "macs": row.get("mac_count") or 0,
            "tx": fmt_rate(row.get("ifOutOctets_rate")),
            "rx": fmt_rate(row.get("ifInOctets_rate")),
            "type": row.get("ifType") or "",
            "last_change": row.get("ifLastChange") or "",
            "descr": row.get("ifDescr") or "",
            "title": row.get("ifAlias") or "",
        })

    columns = [
        {"key": "device", "label": "Device", "html": True},
        {"key": "interface", "label": "Interface", "html": True},
        {"key": "admin", "label": "Admin", "html": True},
        {"key": "oper", "label": "Oper", "html": True},
        {"key": "speed", "label": "Speed"},
        {"key": "macs", "label": "MACs"},
        {"key": "tx", "label": "Tx Bits/Sec"},
        {"key": "rx", "label": "Rx Bits/Sec"},
        {"key": "type", "label": "Type"},
        {"key": "last_change", "label": "Last Change"},
        {"key": "descr", "label": "Description"},
        {"key": "title", "label": "Title"},
    ]

    return {
        "title": "Unused Interfaces",
        "subtitle": f"Showing {len(rows)} likely unused interfaces",
        "q": q,
        "limit": limit,
        "columns": columns,
        "rows": rows,
        "selected_devices": selected_devices,
        "available_devices": available_devices,
        "selected_ids_csv": ids_csv(selected_ids),
        "clear_url": make_report_url(prefix, "", limit, selected_ids),
        "clear_selected_url": f"{prefix}/reports/unused-interfaces",
        "reset_url": f"{prefix}/reports/unused-interfaces",
        "export_url": make_report_url(prefix, q, limit, selected_ids).replace(
            "/reports/unused-interfaces",
            "/reports/unused-interfaces.csv",
            1,
        ),
        "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
    }
