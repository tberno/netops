import html
import os
import socket
from typing import Any

import pymysql
import pymysql.cursors


def h(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def db_conn():
    return pymysql.connect(
        host=os.getenv("LIBRENMS_DB_HOST", os.getenv("DB_HOST", os.getenv("MYSQL_HOST", "db"))),
        port=int(os.getenv("LIBRENMS_DB_PORT", os.getenv("DB_PORT", os.getenv("MYSQL_PORT", "3306")))),
        user=os.getenv("LIBRENMS_DB_USER", os.getenv("DB_USER", os.getenv("MYSQL_USER", "librenms"))),
        password=os.getenv("LIBRENMS_DB_PASSWORD", os.getenv("DB_PASSWORD", os.getenv("MYSQL_PASSWORD", ""))),
        database=os.getenv("LIBRENMS_DB_NAME", os.getenv("DB_NAME", os.getenv("MYSQL_DATABASE", "librenms"))),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        charset="utf8mb4",
    )


def fetch_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone() or {}


def fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())


def safe_query(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    try:
        return fetch_all(sql, params)
    except Exception:
        return []


def safe_float(value: Any) -> float:
    try:
        return float(value or 0)
    except Exception:
        return 0.0


def fmt_ip(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            if len(raw) == 4:
                return socket.inet_ntop(socket.AF_INET, raw)
            if len(raw) == 16:
                return socket.inet_ntop(socket.AF_INET6, raw)
        except Exception:
            return ""

    text = str(value)
    if text.startswith("b'") or text.startswith('b"'):
        return ""

    return text


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
    for key in ("display", "display_name", "sysName", "sys_name"):
        value = row.get(key)
        if value and not looks_like_ip(value):
            return str(value)

    for key in ("hostname", "device"):
        value = row.get(key)
        if value:
            return str(value)

    return fmt_ip(row.get("ip_addr") or row.get("ip"))


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


def status_class(value: Any) -> str:
    raw = str(value or "").strip().lower()

    if raw in ("up", "ok", "online", "active", "1"):
        return "good"
    if raw in ("down", "critical", "offline", "failed", "0"):
        return "bad"
    if raw in ("disabled", "admin down", "shutdown"):
        return "warn"

    return "neutral"


def device_catalog() -> list[dict[str, Any]]:
    return safe_query("""
        SELECT
            d.device_id,
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)) AS device,
            d.hostname,
            d.sysName,
            INET6_NTOA(d.ip) AS ip_addr,
            d.status
        FROM devices d
        ORDER BY device
        LIMIT 2500
    """)


def device_page_context(device_id: int) -> dict[str, Any]:
    dev = fetch_one("""
        SELECT
            d.device_id,
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)) AS device,
            COALESCE(NULLIF(d.sysName,''), NULLIF(d.hostname,''), INET6_NTOA(d.ip)) AS friendly_name,
            d.hostname,
            d.sysName,
            INET6_NTOA(d.ip) AS ip_addr,
            d.os,
            d.hardware,
            d.version,
            d.location_id AS location,
            d.status,
            d.uptime,
            d.last_polled
        FROM devices d
        WHERE d.device_id = %s
    """, (device_id,))

    if not dev:
        raise ValueError(f"Device not found: {device_id}")

    display_name = dev.get("friendly_name") or dev.get("sysName") or dev.get("hostname") or dev.get("ip_addr") or str(device_id)

    try:
        for catalog_row in device_catalog():
            if str(catalog_row.get("device_id")) == str(device_id):
                catalog_label = device_label(catalog_row)
                if catalog_label:
                    display_name = catalog_label
                break
    except Exception:
        pass

    ports = safe_query("""
        SELECT
            p.*,
            CASE
                WHEN p.ifLastChange IS NULL OR p.ifLastChange = 0 OR d.uptime IS NULL OR d.last_polled IS NULL THEN NULL
                ELSE DATE_SUB(d.last_polled, INTERVAL CAST(GREATEST(d.uptime - (p.ifLastChange / 100), 0) AS UNSIGNED) SECOND)
            END AS ifLastChange_at,
            COALESCE(f.mac_count, 0) AS mac_count
        FROM ports p
        JOIN devices d ON d.device_id = p.device_id
        LEFT JOIN (
            SELECT port_id, COUNT(*) AS mac_count
            FROM ports_fdb
            GROUP BY port_id
        ) f ON f.port_id = p.port_id
        WHERE p.device_id = %s
        ORDER BY
            CASE WHEN p.ifName REGEXP '^[a-zA-Z]+-[0-9]+/[0-9]+/[0-9]+' THEN 0 ELSE 1 END,
            p.ifName
    """, (device_id,))

    cpu = safe_query("""
        SELECT processor_descr AS descr, processor_usage AS pct
        FROM processors
        WHERE device_id = %s
        ORDER BY processor_usage DESC
        LIMIT 12
    """, (device_id,))

    mem = safe_query("""
        SELECT mempool_descr AS descr, mempool_perc AS pct
        FROM mempools
        WHERE device_id = %s
        ORDER BY mempool_perc DESC
        LIMIT 12
    """, (device_id,))

    storage = safe_query("""
        SELECT storage_descr AS descr, storage_perc AS pct
        FROM storage
        WHERE device_id = %s
        ORDER BY storage_perc DESC
        LIMIT 20
    """, (device_id,))

    events = safe_query("""
        SELECT datetime, type, severity, message
        FROM eventlog
        WHERE device_id = %s
        ORDER BY datetime DESC
        LIMIT 30
    """, (device_id,))

    summary = {
        "interfaces": len(ports),
        "up": sum(1 for row in ports if str(row.get("ifOperStatus") or "").lower() == "up"),
        "down": sum(1 for row in ports if str(row.get("ifOperStatus") or "").lower() == "down"),
        "admin_down": sum(1 for row in ports if str(row.get("ifAdminStatus") or "").lower() == "down"),
    }

    problem_ports = [
        row for row in ports
        if str(row.get("ifOperStatus") or "").lower() != "up"
        and str(row.get("ifAdminStatus") or "").lower() == "up"
    ][:12]

    busy_ports = sorted(
        ports,
        key=lambda row: safe_float(row.get("ifInOctets_rate")) + safe_float(row.get("ifOutOctets_rate")),
        reverse=True,
    )[:15]

    if ports and all((safe_float(row.get("ifInOctets_rate")) + safe_float(row.get("ifOutOctets_rate"))) == 0 for row in busy_ports):
        busy_ports = ports[:15]

    def port_row(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "port_id": row.get("port_id"),
            "interface": row.get("ifName") or row.get("ifDescr") or row.get("ifIndex") or "",
            "status": row.get("ifOperStatus") or "",
            "status_class": status_class(row.get("ifOperStatus")),
            "speed": fmt_speed(row.get("ifSpeed")),
            "in": fmt_rate(row.get("ifInOctets_rate")),
            "out": fmt_rate(row.get("ifOutOctets_rate")),
            "errors": safe_float(row.get("ifInErrors_rate")) + safe_float(row.get("ifOutErrors_rate")),
            "mac_count": row.get("mac_count") or 0,
            "title": row.get("ifAlias") or row.get("ifDescr") or "",
        }

    vitals = []

    for row in cpu:
        vitals.append({"type": "CPU", "value": f"{row.get('pct')}%", "descr": row.get("descr")})

    for row in mem:
        vitals.append({"type": "Mem", "value": f"{row.get('pct')}%", "descr": row.get("descr")})

    for row in storage:
        vitals.append({"type": "Disk", "value": f"{row.get('pct')}%", "descr": row.get("descr")})

    librenms_base = os.getenv("LIBRENMS_BASE_URL", "").rstrip("/")
    if librenms_base:
        librenms_url = f"{librenms_base}/device/device={device_id}/"
    else:
        librenms_url = f"/device/device={device_id}/"

    return {
        "device_id": device_id,
        "device": dev,
        "devices": device_catalog(),
        "display_name": display_name,
        "ip_addr": fmt_ip(dev.get("ip_addr") or dev.get("ip")),
        "summary": summary,
        "problem_ports": [port_row(row) for row in problem_ports],
        "busy_ports": [port_row(row) for row in busy_ports],
        "vitals": vitals,
        "events": events,
        "librenms_url": librenms_url,
    }
