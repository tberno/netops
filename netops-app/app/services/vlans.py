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

    path = f"{prefix}/reports/vlans"

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


def vlans_context(prefix: str, q: str = "", device_ids: str = "", limit: int = 500):
    q = (q or "").strip()

    try:
        limit = int(limit)
    except Exception:
        limit = 500

    limit = max(1, min(limit, 10000))
    selected_ids = selected_device_ids(device_ids)

    vlan_cols = table_columns("vlans")
    selected_devices, available_devices = switch_picker_context(prefix, selected_ids, q, limit)

    required = {"device_id", "vlan_vlan"}
    missing = sorted(required - vlan_cols)

    if missing:
        return {
            "title": "VLANs",
            "subtitle": "LibreNMS vlans schema mismatch",
            "q": q,
            "limit": limit,
            "columns": [{"key": "error", "label": "Error"}],
            "rows": [{"error": "Missing columns in vlans: " + ", ".join(missing)}],
            "selected_devices": selected_devices,
            "available_devices": available_devices,
            "selected_ids_csv": ids_csv(selected_ids),
            "clear_url": make_report_url(prefix, "", limit, selected_ids),
            "clear_selected_url": f"{prefix}/reports/vlans",
            "reset_url": f"{prefix}/reports/vlans",
            "export_url": make_report_url(prefix, q, limit, selected_ids).replace("/reports/vlans", "/reports/vlans.csv", 1),
            "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
        }

    vlan_id_select = "v.vlan_id AS vlan_db_id" if "vlan_id" in vlan_cols else "NULL AS vlan_db_id"
    vlan_name_select = "v.vlan_name AS vlan_name" if "vlan_name" in vlan_cols else "NULL AS vlan_name"
    vlan_type_select = "v.vlan_type AS vlan_type" if "vlan_type" in vlan_cols else "NULL AS vlan_type"
    vlan_mtu_select = "v.vlan_mtu AS vlan_mtu" if "vlan_mtu" in vlan_cols else "NULL AS vlan_mtu"
    vlan_domain_select = "v.vlan_domain AS vlan_domain" if "vlan_domain" in vlan_cols else "NULL AS vlan_domain"

    where_parts = []
    params: list[Any] = []

    if selected_ids:
        where_parts.append("d.device_id IN (" + ",".join(["%s"] * len(selected_ids)) + ")")
        params.extend(selected_ids)

    if q:
        like_parts = [
            "d.hostname LIKE %s",
            "d.sysName LIKE %s",
            "CAST(v.vlan_vlan AS CHAR) LIKE %s",
        ]
        params.extend([f"%{q}%"] * 3)

        if "vlan_name" in vlan_cols:
            like_parts.append("v.vlan_name LIKE %s")
            params.append(f"%{q}%")

        if "vlan_domain" in vlan_cols:
            like_parts.append("v.vlan_domain LIKE %s")
            params.append(f"%{q}%")

        if "vlan_type" in vlan_cols:
            like_parts.append("v.vlan_type LIKE %s")
            params.append(f"%{q}%")

        where_parts.append("(" + " OR ".join(like_parts) + ")")

    where = "WHERE " + " AND ".join(where_parts) if where_parts else ""

    params.append(limit)

    raw_rows = fetch_all(f"""
        SELECT
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)) AS device,
            d.hostname,
            d.device_id,
            {vlan_id_select},
            v.vlan_vlan AS vlan,
            {vlan_name_select},
            {vlan_domain_select},
            {vlan_type_select},
            {vlan_mtu_select}
        FROM vlans v
        JOIN devices d ON d.device_id = v.device_id
        {where}
        ORDER BY
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)),
            v.vlan_vlan
        LIMIT %s
    """, tuple(params))

    rows = []
    for row in raw_rows:
        rows.append({
            "device": device_anchor(prefix, row),
            "vlan": row.get("vlan") or "",
            "name": row.get("vlan_name") or "",
            "domain": row.get("vlan_domain") or "",
            "type": row.get("vlan_type") or "",
            "mtu": row.get("vlan_mtu") or "",
            "id": row.get("vlan_db_id") or "",
        })

    columns = [
        {"key": "device", "label": "Device", "html": True},
        {"key": "vlan", "label": "VLAN"},
        {"key": "name", "label": "Name"},
        {"key": "domain", "label": "Domain"},
        {"key": "type", "label": "Type"},
        {"key": "mtu", "label": "MTU"},
        {"key": "id", "label": "DB ID"},
    ]

    return {
        "title": "VLANs",
        "subtitle": f"Showing {len(rows)} VLAN entries",
        "q": q,
        "limit": limit,
        "columns": columns,
        "rows": rows,
        "selected_devices": selected_devices,
        "available_devices": available_devices,
        "selected_ids_csv": ids_csv(selected_ids),
        "clear_url": make_report_url(prefix, "", limit, selected_ids),
        "clear_selected_url": f"{prefix}/reports/vlans",
        "reset_url": f"{prefix}/reports/vlans",
        "export_url": make_report_url(prefix, q, limit, selected_ids).replace(
            "/reports/vlans",
            "/reports/vlans.csv",
            1,
        ),
        "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
    }
