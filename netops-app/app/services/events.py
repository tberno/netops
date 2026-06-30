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

    path = f"{prefix}/reports/events"

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


def severity_badge(value: Any) -> str:
    raw = str(value or "").strip()
    lower = raw.lower()

    if lower in {"ok", "info", "notice", "normal", "0"}:
        return f'<span class="badge up">{h(raw or "info")}</span>'

    if lower in {"warn", "warning", "alert", "1"}:
        return f'<span class="badge warn">{h(raw or "warn")}</span>'

    if lower in {"error", "critical", "crit", "down", "2", "3", "4", "5"}:
        return f'<span class="badge down">{h(raw or "error")}</span>'

    return f'<span class="badge warn">{h(raw or "event")}</span>'


def first_existing(cols: set[str], names: list[str]) -> str | None:
    for name in names:
        if name in cols:
            return name
    return None


def events_context(prefix: str, q: str = "", device_ids: str = "", limit: int = 500):
    q = (q or "").strip()

    try:
        limit = int(limit)
    except Exception:
        limit = 500

    limit = max(1, min(limit, 10000))
    selected_ids = selected_device_ids(device_ids)

    event_cols = table_columns("eventlog")
    selected_devices, available_devices = switch_picker_context(prefix, selected_ids, q, limit)

    if not event_cols:
        return {
            "title": "Events",
            "subtitle": "eventlog table not found",
            "q": q,
            "limit": limit,
            "columns": [{"key": "error", "label": "Error"}],
            "rows": [{"error": "Could not read LibreNMS eventlog table."}],
            "selected_devices": selected_devices,
            "available_devices": available_devices,
            "selected_ids_csv": ids_csv(selected_ids),
            "clear_url": make_report_url(prefix, "", limit, selected_ids),
            "clear_selected_url": f"{prefix}/reports/events",
            "reset_url": f"{prefix}/reports/events",
            "export_url": make_report_url(prefix, q, limit, selected_ids).replace("/reports/events", "/reports/events.csv", 1),
            "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
        }

    id_col = first_existing(event_cols, ["event_id", "id"])
    device_col = "device_id" if "device_id" in event_cols else None
    time_col = first_existing(event_cols, ["datetime", "timestamp", "time", "created_at", "updated_at"])
    message_col = first_existing(event_cols, ["message", "msg", "event", "details"])
    type_col = first_existing(event_cols, ["type", "event_type", "entity_type"])
    severity_col = first_existing(event_cols, ["severity", "level", "priority"])
    username_col = first_existing(event_cols, ["username", "user", "uid"])

    if not time_col or not message_col:
        return {
            "title": "Events",
            "subtitle": "LibreNMS eventlog schema mismatch",
            "q": q,
            "limit": limit,
            "columns": [{"key": "error", "label": "Error"}],
            "rows": [{"error": "Could not find expected time/message columns in eventlog. Columns: " + ", ".join(sorted(event_cols))}],
            "selected_devices": selected_devices,
            "available_devices": available_devices,
            "selected_ids_csv": ids_csv(selected_ids),
            "clear_url": make_report_url(prefix, "", limit, selected_ids),
            "clear_selected_url": f"{prefix}/reports/events",
            "reset_url": f"{prefix}/reports/events",
            "export_url": make_report_url(prefix, q, limit, selected_ids).replace("/reports/events", "/reports/events.csv", 1),
            "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
        }

    select_parts = [
        f"e.{time_col} AS event_time",
        f"e.{message_col} AS message",
        f"e.{id_col} AS event_id" if id_col else "NULL AS event_id",
        f"e.{device_col} AS device_id" if device_col else "NULL AS device_id",
        f"e.{type_col} AS event_type" if type_col else "NULL AS event_type",
        f"e.{severity_col} AS severity" if severity_col else "NULL AS severity",
        f"e.{username_col} AS username" if username_col else "NULL AS username",
    ]

    if device_col:
        select_parts.append("COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)) AS device")
        join_sql = f"LEFT JOIN devices d ON d.device_id = e.{device_col}"
    else:
        select_parts.append("NULL AS device")
        join_sql = ""

    where_parts = []
    params: list[Any] = []

    if selected_ids and device_col:
        where_parts.append("e.device_id IN (" + ",".join(["%s"] * len(selected_ids)) + ")")
        params.extend(selected_ids)

    if q:
        like_parts = [
            f"CAST(e.{message_col} AS CHAR) LIKE %s",
            f"CAST(e.{time_col} AS CHAR) LIKE %s",
        ]
        params.extend([f"%{q}%"] * 2)

        if device_col:
            like_parts.append("d.hostname LIKE %s")
            like_parts.append("d.sysName LIKE %s")
            params.extend([f"%{q}%"] * 2)

        if type_col:
            like_parts.append(f"CAST(e.{type_col} AS CHAR) LIKE %s")
            params.append(f"%{q}%")

        if severity_col:
            like_parts.append(f"CAST(e.{severity_col} AS CHAR) LIKE %s")
            params.append(f"%{q}%")

        if username_col:
            like_parts.append(f"CAST(e.{username_col} AS CHAR) LIKE %s")
            params.append(f"%{q}%")

        where_parts.append("(" + " OR ".join(like_parts) + ")")

    where = "WHERE " + " AND ".join(where_parts) if where_parts else ""

    order_parts = [f"e.{time_col} DESC"]
    if id_col:
        order_parts.append(f"e.{id_col} DESC")

    params.append(limit)

    raw_rows = fetch_all(f"""
        SELECT
            {", ".join(select_parts)}
        FROM eventlog e
        {join_sql}
        {where}
        ORDER BY {", ".join(order_parts)}
        LIMIT %s
    """, tuple(params))

    rows = []
    for row in raw_rows:
        rows.append({
            "time": row.get("event_time") or "",
            "device": device_anchor(prefix, row) if row.get("device_id") else "",
            "severity": severity_badge(row.get("severity")),
            "type": row.get("event_type") or "",
            "message": row.get("message") or "",
            "user": row.get("username") or "",
            "id": row.get("event_id") or "",
        })

    columns = [
        {"key": "time", "label": "Time"},
        {"key": "device", "label": "Device", "html": True},
        {"key": "severity", "label": "Severity", "html": True},
        {"key": "type", "label": "Type"},
        {"key": "message", "label": "Message"},
        {"key": "user", "label": "User"},
        {"key": "id", "label": "Event ID"},
    ]

    return {
        "title": "Events",
        "subtitle": f"Showing {len(rows)} recent events",
        "q": q,
        "limit": limit,
        "columns": columns,
        "rows": rows,
        "selected_devices": selected_devices,
        "available_devices": available_devices,
        "selected_ids_csv": ids_csv(selected_ids),
        "clear_url": make_report_url(prefix, "", limit, selected_ids),
        "clear_selected_url": f"{prefix}/reports/events",
        "reset_url": f"{prefix}/reports/events",
        "export_url": make_report_url(prefix, q, limit, selected_ids).replace(
            "/reports/events",
            "/reports/events.csv",
            1,
        ),
        "limit_options": [100, 250, 500, 1000, 2000, 5000, 10000],
    }
