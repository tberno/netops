import os
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Any


NTP_DELTA = 2208988800

DEFAULT_TARGETS = [
    "time.middlebury.edu",
    "zeus.middlebury.edu",
    "hera.middlebury.edu",
    "time.cloudflare.com",
    "time.google.com",
    "time.aws.com",
    "time.nist.gov",
]


def _split_targets() -> list[str]:
    raw = os.getenv("NTP_DASHBOARD_TARGETS", "").strip()
    if not raw:
        return DEFAULT_TARGETS
    return [x.strip() for x in raw.split(",") if x.strip()]


def _role_for_host(host: str) -> str:
    h = host.lower()
    if h in ("time.middlebury.edu", "zeus.middlebury.edu", "hera.middlebury.edu"):
        return "middlebury"
    return "reference"


def _label_for_role(role: str) -> str:
    if role == "middlebury":
        return "Middlebury monitored"
    return "Third-party reference"


def _status_from_offset(offset_ms: float | None, ok: bool) -> tuple[str, str]:
    if not ok or offset_ms is None:
        return "critical", "CRITICAL"

    abs_offset = abs(offset_ms)

    if abs_offset <= 100:
        return "good", "OK"

    if abs_offset <= 500:
        return "warn", "WARN"

    return "critical", "CRITICAL"


def _fmt_ms(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.2f} ms"


def _fmt_time(ts: float | None) -> str:
    if ts is None:
        return "—"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ntp_query(host: str, timeout: float = 2.5) -> dict[str, Any]:
    role = _role_for_host(host)

    result: dict[str, Any] = {
        "host": host,
        "role": role,
        "role_label": _label_for_role(role),
        "resolved_ip": "",
        "ok": False,
        "state": "critical",
        "status": "CRITICAL",
        "error": "",
        "stratum": None,
        "version": None,
        "mode": None,
        "leap": None,
        "offset_ms": None,
        "delay_ms": None,
        "server_time": None,
        "server_time_text": "—",
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    try:
        resolved_ip = socket.gethostbyname(host)
        result["resolved_ip"] = resolved_ip
    except Exception as exc:
        result["error"] = f"DNS resolution failed: {exc}"
        return result

    packet = bytearray(48)
    packet[0] = 0x23  # LI=0, version=4, mode=3 client

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)

            t1 = time.time()
            sock.sendto(packet, (result["resolved_ip"], 123))
            data, _ = sock.recvfrom(512)
            t4 = time.time()

        if len(data) < 48:
            result["error"] = f"Short NTP response: {len(data)} bytes"
            return result

        unpacked = struct.unpack("!12I", data[:48])

        flags = data[0]
        li = (flags >> 6) & 0x3
        version = (flags >> 3) & 0x7
        mode = flags & 0x7
        stratum = data[1]

        recv_seconds = unpacked[8]
        recv_fraction = unpacked[9]
        tx_seconds = unpacked[10]
        tx_fraction = unpacked[11]

        t2 = (recv_seconds - NTP_DELTA) + (recv_fraction / 2**32)
        t3 = (tx_seconds - NTP_DELTA) + (tx_fraction / 2**32)

        offset = ((t2 - t1) + (t3 - t4)) / 2
        delay = (t4 - t1) - (t3 - t2)

        offset_ms = offset * 1000
        delay_ms = delay * 1000

        state, status = _status_from_offset(offset_ms, True)

        result.update(
            {
                "ok": True,
                "state": state,
                "status": status,
                "stratum": stratum,
                "version": version,
                "mode": mode,
                "leap": li,
                "offset_ms": offset_ms,
                "delay_ms": delay_ms,
                "server_time": t3,
                "server_time_text": _fmt_time(t3),
            }
        )

        return result

    except socket.timeout:
        result["error"] = "NTP query timed out on UDP/123"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def ntp_dashboard_context() -> dict[str, Any]:
    targets = _split_targets()
    checks = [_ntp_query(t) for t in targets]

    monitored = [c for c in checks if c["role"] == "middlebury"]
    references = [c for c in checks if c["role"] == "reference"]

    service_good = sum(1 for c in monitored if c["state"] == "good")
    service_warn = sum(1 for c in monitored if c["state"] == "warn")
    service_critical = sum(1 for c in monitored if c["state"] == "critical")

    ref_good = sum(1 for c in references if c["state"] == "good")
    ref_warn = sum(1 for c in references if c["state"] == "warn")
    ref_critical = sum(1 for c in references if c["state"] == "critical")

    primary = checks[0] if checks else None

    if service_critical:
        overall_state = "critical"
        overall_status = "CRITICAL"
    elif service_warn:
        overall_state = "warn"
        overall_status = "WARN"
    else:
        overall_state = "good"
        overall_status = "OK"

    return {
        "title": "NTP Status",
        "checks": checks,
        "monitored_checks": monitored,
        "reference_checks": references,
        "primary": primary,
        "summary": {
            "overall_state": overall_state,
            "overall_status": overall_status,
            "good": service_good,
            "warn": service_warn,
            "critical": service_critical,
            "targets": len(monitored),
            "reference_good": ref_good,
            "reference_warn": ref_warn,
            "reference_critical": ref_critical,
            "reference_targets": len(references),
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        "fmt_ms": _fmt_ms,
    }
