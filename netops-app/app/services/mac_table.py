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


def norm_sql(expr: str) -> str:
    return f"LOWER(REPLACE(REPLACE(REPLACE(CAST({expr} AS CHAR), ':', ''), '-', ''), '.', ''))"


def make_report_url(prefix: str, q: str, limit: int, ids: list[int]) -> str:
    params = {}

    if q:
        params["q"] = q

    if limit != 1000:
        params["limit"] = str(limit)

    if ids:
        params["device_ids"] = ids_csv(ids)

    path = f"{prefix}/reports/mac-table"

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

    raw = text.lower()
    raw = raw.replace(":", "").replace("-", "").replace(".", "")

    if len(raw) == 12:
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))

    return text


def clean_query_mac(value: str) -> str:
    return str(value or "").lower().replace(":", "").replace("-", "").replace(".", "").strip()


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


def mac_table_context(prefix: str, q: str = "", device_ids: str = "", limit: int = 1000):
    q = (q or "").strip()

    try:
        limit = int(limit)
    except Exception:
        limit = 1000

    limit = max(1, min(limit, 10000))
    selected_ids = selected_device_ids(device_ids)

    fdb_cols = table_columns("ports_fdb")
    ipv4_mac_cols = table_columns("ipv4_mac")
    ipv4_addr_cols = table_columns("ipv4_addresses")
    vlan_cols = table_columns("vlans")

    mac_col = "mac_address" if "mac_address" in fdb_cols else None
    vlan_col = "vlan_id" if "vlan_id" in fdb_cols else None

    if not mac_col:
        selected_devices, available_devices = switch_picker_context(prefix, selected_ids, q, limit)
        return {
            "title": "MAC Table",
            "subtitle": "ports_fdb.mac_address column not found",
            "q": q,
            "limit": limit,
            "columns": [{"key": "error", "label": "Error"}],
            "rows": [{"error": "Could not find mac_address in ports_fdb. Run SHOW COLUMNS FROM ports_fdb; to verify schema."}],
            "selected_devices": selected_devices,
            "available_devices": available_devices,
            "selected_ids_csv": ids_csv(selected_ids),
            "clear_url": make_report_url(prefix, "", limit, selected_ids),
            "reset_url": f"{prefix}/reports/mac-table",
        "clear_selected_url": f"{prefix}/reports/mac-table",
            "export_url": make_report_url(prefix, q, limit, selected_ids).replace("/reports/mac-table", "/reports/mac-table.csv", 1),
            "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
        }

    joins = []
    select_extra = []

    if (
        "mac_address" in ipv4_mac_cols
        and "ipv4_address_id" in ipv4_mac_cols
        and "ipv4_address_id" in ipv4_addr_cols
        and "ipv4_address" in ipv4_addr_cols
    ):
        joins.append(f"""
        LEFT JOIN (
            SELECT
                {norm_sql('im.mac_address')} AS mac_norm,
                MAX(ia.ipv4_address) AS ip_addr
            FROM ipv4_mac im
            JOIN ipv4_addresses ia ON ia.ipv4_address_id = im.ipv4_address_id
            GROUP BY {norm_sql('im.mac_address')}
        ) ipm ON ipm.mac_norm = {norm_sql(f'f.{mac_col}')}
        """)
        select_extra.append("ipm.ip_addr AS ip_addr")
    else:
        select_extra.append("NULL AS ip_addr")

    if vlan_col and "vlan_vlan" in vlan_cols:
        vlan_name_col = "vlan_name" if "vlan_name" in vlan_cols else None
        joins.append(f"""
        LEFT JOIN vlans v ON v.device_id = d.device_id AND v.vlan_vlan = f.{vlan_col}
        """)
        if vlan_name_col:
            select_extra.append(f"v.{vlan_name_col} AS vlan_name")
        else:
            select_extra.append("NULL AS vlan_name")
    else:
        select_extra.append("NULL AS vlan_name")

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
            f"f.{mac_col} LIKE %s",
            f"{norm_sql(f'f.{mac_col}')} LIKE %s",
        ]

        params.extend([f"%{q}%"] * 6)
        params.append(f"%{clean_query_mac(q)}%")

        if vlan_col:
            like_parts.append(f"CAST(f.{vlan_col} AS CHAR) LIKE %s")
            params.append(f"%{q}%")

        where_parts.append("(" + " OR ".join(like_parts) + ")")

    where = "WHERE " + " AND ".join(where_parts) if where_parts else ""

    vlan_select = f"f.{vlan_col} AS vlan" if vlan_col else "NULL AS vlan"
    extra_select_sql = ",\n            ".join(select_extra)
    join_sql = "\n".join(joins)

    if "updated_at" in fdb_cols:
        order_sql = "f.updated_at DESC"
    elif "created_at" in fdb_cols:
        order_sql = "f.created_at DESC"
    elif "ports_fdb_id" in fdb_cols:
        order_sql = "f.ports_fdb_id DESC"
    else:
        order_sql = "COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)), vlan, p.ifIndex, f.mac_address"

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
            f.{mac_col} AS mac,
            {vlan_select},
            {extra_select_sql}
        FROM ports_fdb f
        JOIN ports p ON p.port_id = f.port_id
        JOIN devices d ON d.device_id = p.device_id
        {join_sql}
        {where}
        ORDER BY
            {order_sql}
        LIMIT %s
    """, tuple(params))

    rows = []
    for row in raw_rows:
        vlan_value = row.get("vlan") or ""
        vlan_name = row.get("vlan_name") or ""

        if vlan_value and vlan_name:
            vlan_display = f"{vlan_value} - {vlan_name}"
        else:
            vlan_display = vlan_value or vlan_name

        rows.append({
            "switch": device_anchor(prefix, row),
            "port": interface_anchor(prefix, row),
            "learned_mac": clean_mac(row.get("mac")),
            "ip": row.get("ip_addr") or "",
            "vlan": vlan_display,
            "ifindex": row.get("ifIndex") or "",
            "descr": row.get("ifDescr") or "",
            "title": row.get("ifAlias") or "",
        })

    selected_devices, available_devices = switch_picker_context(prefix, selected_ids, q, limit)

    columns = [
        {"key": "switch", "label": "Switch", "html": True},
        {"key": "port", "label": "Port", "html": True},
        {"key": "learned_mac", "label": "Learned MAC"},
        {"key": "ip", "label": "IP"},
        {"key": "vlan", "label": "VLAN"},
        {"key": "ifindex", "label": "IfIndex"},
        {"key": "descr", "label": "Description"},
        {"key": "title", "label": "Title"},
    ]

    return {
        "title": "MAC Table",
        "subtitle": f"Showing {len(rows)} learned MAC entries",
        "q": q,
        "limit": limit,
        "columns": columns,
        "rows": rows,
        "selected_devices": selected_devices,
        "available_devices": available_devices,
        "selected_ids_csv": ids_csv(selected_ids),
        "clear_url": make_report_url(prefix, "", limit, selected_ids),
        "reset_url": f"{prefix}/reports/mac-table",
        "clear_selected_url": f"{prefix}/reports/mac-table",
        "export_url": make_report_url(prefix, q, limit, selected_ids).replace(
            "/reports/mac-table",
            "/reports/mac-table.csv",
            1,
        ),
        "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
    }
