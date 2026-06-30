import html
from typing import Any

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


def device_name(row: dict[str, Any]) -> str:
    return str(
        row.get("sysName")
        or row.get("hostname")
        or row.get("ip_addr")
        or row.get("device_id")
        or ""
    )


def badge(value: Any) -> str:
    raw = str(value or "").strip().lower()

    if raw in {"1", "up", "ok", "online", "active"}:
        return '<span class="badge up">up</span>'

    if raw in {"0", "down", "critical", "offline", "failed"}:
        return '<span class="badge down">down</span>'

    return f'<span class="badge warn">{h(raw or "unknown")}</span>'


def device_context(prefix: str, device_id: int) -> dict[str, Any]:
    devices = fetch_all(
        """
        SELECT
            d.*,
            INET6_NTOA(d.ip) AS ip_addr
        FROM devices d
        WHERE d.device_id = %s
        LIMIT 1
        """,
        (device_id,),
    )

    if not devices:
        return {
            "title": "Device not found",
            "device": None,
            "facts": [],
            "columns": [],
            "rows": [],
            "back_url": f"{prefix}/reports/interface-statistics",
        }

    device = devices[0]
    name = device_name(device)

    facts = [
        ("Hostname", device.get("hostname")),
        ("SysName", device.get("sysName")),
        ("IP", device.get("ip_addr")),
        ("OS", device.get("os")),
        ("Hardware", device.get("hardware")),
        ("Version", device.get("version")),
        ("Type", device.get("type")),
        ("Status", "up" if str(device.get("status")) == "1" else "down"),
        ("Location", device.get("location")),
        ("Purpose", device.get("purpose")),
        ("Last polled", device.get("last_polled")),
    ]

    ports = fetch_all(
        """
        SELECT
            p.port_id,
            p.ifName,
            p.ifDescr,
            p.ifAlias,
            p.ifOperStatus,
            p.ifAdminStatus,
            p.ifSpeed,
            p.ifInOctets_rate,
            p.ifOutOctets_rate,
            p.ifInErrors_rate,
            p.ifOutErrors_rate,
            COALESCE(f.mac_count, 0) AS mac_count
        FROM ports p
        LEFT JOIN (
            SELECT port_id, COUNT(*) AS mac_count
            FROM ports_fdb
            GROUP BY port_id
        ) f ON f.port_id = p.port_id
        WHERE p.device_id = %s
        ORDER BY
            CASE WHEN p.ifOperStatus = 'up' THEN 0 ELSE 1 END,
            p.ifIndex,
            p.ifName
        """,
        (device_id,),
    )

    rows = []
    for port in ports:
        label = port.get("ifName") or port.get("ifDescr") or port.get("port_id")
        rows.append({
            "interface": f'<a href="{prefix}/interface/{h(port.get("port_id"))}">{h(label)}</a>',
            "status": badge(port.get("ifOperStatus")),
            "admin": h(port.get("ifAdminStatus") or ""),
            "speed": fmt_speed(port.get("ifSpeed")),
            "macs": port.get("mac_count") or 0,
            "tx": fmt_rate(port.get("ifOutOctets_rate")),
            "rx": fmt_rate(port.get("ifInOctets_rate")),
            "tx_errors": port.get("ifOutErrors_rate") or 0,
            "rx_errors": port.get("ifInErrors_rate") or 0,
            "title": port.get("ifAlias") or "",
        })

    columns = [
        {"key": "interface", "label": "Interface", "html": True},
        {"key": "status", "label": "Status", "html": True},
        {"key": "admin", "label": "Admin"},
        {"key": "speed", "label": "Speed"},
        {"key": "macs", "label": "MACs"},
        {"key": "tx", "label": "Tx Bits/Sec"},
        {"key": "rx", "label": "Rx Bits/Sec"},
        {"key": "tx_errors", "label": "Tx Errors"},
        {"key": "rx_errors", "label": "Rx Errors"},
        {"key": "title", "label": "Title"},
    ]

    return {
        "title": name,
        "device": device,
        "facts": [(k, v) for k, v in facts if v not in (None, "")],
        "columns": columns,
        "rows": rows,
        "back_url": f"{prefix}/reports/interface-statistics",
    }


def interface_context(prefix: str, port_id: int) -> dict[str, Any]:
    rows = fetch_all(
        """
        SELECT
            d.device_id,
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)) AS device_name,
            INET6_NTOA(d.ip) AS ip_addr,
            p.*,
            COALESCE(f.mac_count, 0) AS mac_count
        FROM ports p
        JOIN devices d ON d.device_id = p.device_id
        LEFT JOIN (
            SELECT port_id, COUNT(*) AS mac_count
            FROM ports_fdb
            GROUP BY port_id
        ) f ON f.port_id = p.port_id
        WHERE p.port_id = %s
        LIMIT 1
        """,
        (port_id,),
    )

    if not rows:
        return {
            "title": "Interface not found",
            "port": None,
            "facts": [],
            "back_url": f"{prefix}/reports/interface-statistics",
        }

    port = rows[0]
    label = port.get("ifName") or port.get("ifDescr") or port.get("port_id")

    facts = [
        ("Device", f'<a href="{prefix}/device/{h(port.get("device_id"))}">{h(port.get("device_name"))}</a>'),
        ("IP", port.get("ip_addr")),
        ("Interface", label),
        ("Description", port.get("ifDescr")),
        ("Alias / Title", port.get("ifAlias")),
        ("Oper status", badge(port.get("ifOperStatus"))),
        ("Admin status", port.get("ifAdminStatus")),
        ("Speed", fmt_speed(port.get("ifSpeed"))),
        ("MAC count", port.get("mac_count") or 0),
        ("Tx Bits/Sec", fmt_rate(port.get("ifOutOctets_rate"))),
        ("Rx Bits/Sec", fmt_rate(port.get("ifInOctets_rate"))),
        ("Tx Errors", port.get("ifOutErrors_rate") or 0),
        ("Rx Errors", port.get("ifInErrors_rate") or 0),
    ]

    return {
        "title": f"{port.get('device_name')} / {label}",
        "port": port,
        "facts": [(k, v) for k, v in facts if v not in (None, "")],
        "back_url": f"{prefix}/device/{port.get('device_id')}",
    }
