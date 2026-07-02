from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.ntp_dashboard import ntp_dashboard_context


DEFAULT_BROKER_URL = "http://127.0.0.1:5052/webhook/netops"
DEFAULT_STATE_FILE = "/var/lib/netops-synthetic-alerts/state.json"
DEFAULT_DASHBOARD_URL = "https://raccoon.middlebury.edu/netops-v4/dashboards/time-dns"

DEFAULT_NTP_HOSTS = [
    "zeus.middlebury.edu",
    "hera.middlebury.edu",
    "miis-infoblox1.middlebury.edu",
    "miis-infoblox2.middlebury.edu",
]

DEFAULT_DNS_SYNC_ZONES = [
    "middlebury.edu",
]

DEFAULT_DNS_SOURCE_SERVERS = [
    "hera.middlebury.edu",
    "zeus.middlebury.edu",
]

DEFAULT_DNS_CLOUDFLARE_SERVERS = [
    "ns0045.secondary.cloudflare.com",
    "ns0245.secondary.cloudflare.com",
]


@dataclass
class CheckEvent:
    key: str
    ok: bool
    severity: str
    event_type: str
    device: str
    summary: str
    details: str
    link: str


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    return [x.strip() for x in raw.split(",") if x.strip()]


def env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def load_state(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"checks": {}}

    try:
        return json.loads(p.read_text())
    except Exception:
        return {"checks": {}}


def save_state(path: str, state: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(p)


def post_to_broker(url: str, payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    if dry_run:
        print("DRY-RUN payload:")
        print(json.dumps(payload, indent=2, sort_keys=True))
        return {"ok": True, "dry_run": True}

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=10) as response:
        body = response.read().decode("utf-8", "ignore")
        try:
            return json.loads(body)
        except Exception:
            return {"ok": response.status < 300, "raw": body, "status": response.status}


def payload_for(event: CheckEvent, state: str, alert_id: str, severity: str | None = None) -> dict[str, Any]:
    sev = severity or event.severity
    return {
        "state": state,
        "severity": sev,
        "device": event.device,
        "summary": event.summary,
        "rule": event.summary,
        "alert_id": alert_id,
        "event_type": event.event_type,
        "details": event.details,
        "link": event.link,
        "timestamp": utc_now(),
    }


def process_events(
    events: list[CheckEvent],
    state_file: str,
    broker_url: str,
    dry_run: bool = False,
) -> int:
    state = load_state(state_file)
    checks = state.setdefault("checks", {})
    changed = False
    sent = 0

    seen_keys = set()

    for event in events:
        seen_keys.add(event.key)
        previous = checks.get(event.key, {})
        was_open = previous.get("open") is True
        previous_alert_id = previous.get("alert_id")
        previous_severity = previous.get("severity")

        if event.ok:
            if was_open and previous_alert_id:
                payload = payload_for(event, "resolved", previous_alert_id, severity="ok")
                result = post_to_broker(broker_url, payload, dry_run=dry_run)
                print("RECOVERY", event.key, result)
                sent += 1

            checks[event.key] = {
                "open": False,
                "severity": "ok",
                "alert_id": previous_alert_id,
                "last_seen": utc_now(),
                "summary": event.summary,
            }
            changed = True
            continue

        alert_id = f"{event.key}:{event.severity}"

        # Escalation/de-escalation: close the previous severity-specific alert,
        # then open a new one. This keeps Slack updates clean and avoids dedupe hiding escalation.
        if was_open and previous_alert_id and previous_alert_id != alert_id:
            recovery_payload = payload_for(event, "resolved", previous_alert_id, severity="ok")
            result = post_to_broker(broker_url, recovery_payload, dry_run=dry_run)
            print("SEVERITY-CHANGE-RECOVERY", event.key, previous_severity, "->", event.severity, result)
            sent += 1
            was_open = False

        if not was_open:
            payload = payload_for(event, "alert", alert_id)
            result = post_to_broker(broker_url, payload, dry_run=dry_run)
            print("ALERT", event.key, result)
            sent += 1
        else:
            print("OPEN", event.key, event.severity, "- no post")

        checks[event.key] = {
            "open": True,
            "severity": event.severity,
            "alert_id": alert_id,
            "last_seen": utc_now(),
            "summary": event.summary,
        }
        changed = True

    # If a check disappears from the runner config, leave existing state alone.
    # We do not auto-resolve missing checks because a missing evaluator could hide a real issue.

    if changed and not dry_run:
        save_state(state_file, state)

    print(f"Processed {len(events)} checks, sent {sent} broker event(s)")
    return sent


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def ntp_events() -> list[CheckEvent]:
    hosts = set(env_list("NETOPS_ALERT_NTP_HOSTS", DEFAULT_NTP_HOSTS))

    # Absolute offset compares each NTP server to raccoon's local clock.
    # This is disabled by default because a raccoon clock issue can make every
    # healthy NTP server look bad at the same time.
    check_absolute_offset = env_bool("NETOPS_ALERT_NTP_CHECK_ABSOLUTE_OFFSET", False)
    warn_ms = env_float("NETOPS_ALERT_NTP_WARN_MS", 100.0)
    crit_ms = env_float("NETOPS_ALERT_NTP_CRIT_MS", 500.0)

    # Relative spread compares the monitored NTP servers to each other.
    # This catches one bad NTP server without requiring raccoon to be a trusted clock.
    spread_warn_ms = env_float("NETOPS_ALERT_NTP_SPREAD_WARN_MS", 250.0)
    spread_crit_ms = env_float("NETOPS_ALERT_NTP_SPREAD_CRIT_MS", 1000.0)

    link = os.getenv("NETOPS_ALERT_NTP_DASHBOARD_URL", DEFAULT_DASHBOARD_URL)

    ctx = ntp_dashboard_context()
    checks = ctx.get("checks", [])

    selected: list[dict[str, Any]] = []
    found_hosts = set()

    for check in checks:
        host = str(check.get("host") or "")
        if host not in hosts:
            continue
        found_hosts.add(host)
        selected.append(check)

    offset_values = [
        float(c["offset_ms"])
        for c in selected
        if c.get("offset_ms") is not None and c.get("ok")
    ]

    median_offset = None
    if offset_values:
        sorted_offsets = sorted(offset_values)
        mid = len(sorted_offsets) // 2
        if len(sorted_offsets) % 2:
            median_offset = sorted_offsets[mid]
        else:
            median_offset = (sorted_offsets[mid - 1] + sorted_offsets[mid]) / 2.0

    events: list[CheckEvent] = []

    for check in selected:
        host = str(check.get("host") or "")
        offset = check.get("offset_ms")
        state = str(check.get("state") or "").lower()
        status = str(check.get("status") or "").upper()
        error = check.get("error") or ""
        stratum = check.get("stratum")
        resolved_ip = check.get("resolved_ip") or "unresolved"

        bad_reasons = []
        severity = "ok"

        if not check.get("ok"):
            bad_reasons.append("NTP query failed")
            severity = "critical"

        if error:
            bad_reasons.append(f"error={error}")
            severity = "critical"

        if stratum is None:
            bad_reasons.append("stratum is missing")
            severity = "critical"
        elif int(stratum) >= 16:
            bad_reasons.append(f"stratum={stratum}")
            severity = "critical"

        if check_absolute_offset and offset is not None:
            abs_offset = abs(float(offset))
            if abs_offset > crit_ms:
                bad_reasons.append(f"absolute offset {offset:.2f} ms exceeds critical {crit_ms:.0f} ms")
                severity = "critical"
            elif abs_offset > warn_ms and severity != "critical":
                bad_reasons.append(f"absolute offset {offset:.2f} ms exceeds warning {warn_ms:.0f} ms")
                severity = "warning"

        relative_delta = None
        if median_offset is not None and offset is not None:
            relative_delta = float(offset) - median_offset
            abs_delta = abs(relative_delta)

            if abs_delta > spread_crit_ms:
                bad_reasons.append(
                    f"relative NTP offset delta {relative_delta:.2f} ms exceeds critical spread {spread_crit_ms:.0f} ms"
                )
                severity = "critical"
            elif abs_delta > spread_warn_ms and severity != "critical":
                bad_reasons.append(
                    f"relative NTP offset delta {relative_delta:.2f} ms exceeds warning spread {spread_warn_ms:.0f} ms"
                )
                severity = "warning"

        # Do not let dashboard WARN/CRITICAL caused only by absolute raccoon offset
        # trigger Slack when absolute offset alerting is disabled.
        if check_absolute_offset:
            if state == "critical" or status == "CRITICAL":
                severity = "critical"
            elif state == "warn" or status == "WARN":
                if severity != "critical":
                    severity = "warning"

        ok = severity == "ok" and not bad_reasons

        details = "\n".join(
            [
                f"Host: {host}",
                f"Resolved IP: {resolved_ip}",
                f"Status: {status or state or 'unknown'}",
                f"Offset vs raccoon: {offset if offset is not None else 'unknown'} ms",
                f"Median offset across monitored NTP servers: {median_offset if median_offset is not None else 'unknown'} ms",
                f"Relative delta: {relative_delta if relative_delta is not None else 'unknown'} ms",
                f"Absolute offset alerting enabled: {check_absolute_offset}",
                f"Stratum: {stratum if stratum is not None else 'unknown'}",
                f"Server time: {check.get('server_time_text') or 'unknown'}",
                f"Checked: {check.get('checked_at') or utc_now()}",
                "",
                "Reason:",
                "\n".join(f"- {r}" for r in bad_reasons) if bad_reasons else "- NTP service healthy",
            ]
        )

        events.append(
            CheckEvent(
                key=f"ntp:{host}",
                ok=ok,
                severity=severity if severity != "ok" else "ok",
                event_type="ntp",
                device=host,
                summary=f"NTP health check for {host}",
                details=details,
                link=link,
            )
        )

    for host in sorted(hosts - found_hosts):
        events.append(
            CheckEvent(
                key=f"ntp:{host}",
                ok=False,
                severity="critical",
                event_type="ntp",
                device=host,
                summary=f"NTP health check for {host}",
                details=f"Host {host} was not returned by ntp_dashboard_context().",
                link=link,
            )
        )

    return events

def dig_soa_serial(server: str, zone: str) -> tuple[int | None, str]:
    cmd = [
        "dig",
        "+time=2",
        "+tries=1",
        "+short",
        f"@{server}",
        zone,
        "SOA",
    ]

    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except Exception as exc:
        return None, f"dig failed: {exc}"

    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout or f"dig exited {proc.returncode}").strip()

    output = proc.stdout.strip()
    if not output:
        return None, "empty SOA response"

    # SOA short format:
    # mname. rname. serial refresh retry expire minimum
    line = output.splitlines()[0]
    parts = line.split()

    if len(parts) < 3:
        return None, f"unparseable SOA response: {line}"

    try:
        return int(parts[2]), line
    except ValueError:
        return None, f"unparseable SOA serial: {line}"


def dns_sync_events() -> list[CheckEvent]:
    zones = env_list("NETOPS_ALERT_DNS_SYNC_ZONES", DEFAULT_DNS_SYNC_ZONES)
    source_servers = env_list("NETOPS_ALERT_DNS_SOURCE_SERVERS", DEFAULT_DNS_SOURCE_SERVERS)
    cloudflare_servers = env_list("NETOPS_ALERT_DNS_CLOUDFLARE_SERVERS", DEFAULT_DNS_CLOUDFLARE_SERVERS)
    link = os.getenv("NETOPS_ALERT_DNS_DASHBOARD_URL", DEFAULT_DASHBOARD_URL)

    events: list[CheckEvent] = []

    for zone in zones:
        source_results = []
        cf_results = []

        for server in source_servers:
            serial, raw = dig_soa_serial(server, zone)
            source_results.append({"server": server, "serial": serial, "raw": raw})

        for server in cloudflare_servers:
            serial, raw = dig_soa_serial(server, zone)
            cf_results.append({"server": server, "serial": serial, "raw": raw})

        source_serials = [r["serial"] for r in source_results if r["serial"] is not None]
        cf_serials = [r["serial"] for r in cf_results if r["serial"] is not None]

        bad_reasons = []
        severity = "ok"

        source_serial = max(source_serials) if source_serials else None

        if source_serial is None:
            severity = "critical"
            bad_reasons.append("No SOA serial returned from SolidServer source servers")

        for r in source_results:
            if r["serial"] is None:
                severity = "critical"
                bad_reasons.append(f"SolidServer source {r['server']} failed: {r['raw']}")

        for r in cf_results:
            if r["serial"] is None:
                severity = "critical"
                bad_reasons.append(f"Cloudflare secondary {r['server']} failed: {r['raw']}")

        if source_serial is not None and cf_serials:
            behind = [r for r in cf_results if r["serial"] is not None and r["serial"] < source_serial]
            mismatch = [r for r in cf_results if r["serial"] is not None and r["serial"] != source_serial]

            if behind:
                severity = "critical"
                bad_reasons.append(
                    "Cloudflare secondary behind SolidServer: "
                    + ", ".join(f"{r['server']}={r['serial']}" for r in behind)
                    + f", source={source_serial}"
                )
            elif mismatch and severity != "critical":
                severity = "warning"
                bad_reasons.append(
                    "Cloudflare secondary SOA serial mismatch: "
                    + ", ".join(f"{r['server']}={r['serial']}" for r in mismatch)
                    + f", source={source_serial}"
                )

        ok = severity == "ok"

        details_lines = [
            f"Zone: {zone}",
            f"SolidServer source servers: {', '.join(source_servers)}",
            f"Cloudflare secondaries: {', '.join(cloudflare_servers)}",
            f"Expected/source serial: {source_serial if source_serial is not None else 'unknown'}",
            "",
            "SolidServer results:",
        ]

        for r in source_results:
            details_lines.append(f"- {r['server']}: {r['serial'] if r['serial'] is not None else 'FAIL'} ({r['raw']})")

        details_lines.append("")
        details_lines.append("Cloudflare results:")

        for r in cf_results:
            details_lines.append(f"- {r['server']}: {r['serial'] if r['serial'] is not None else 'FAIL'} ({r['raw']})")

        details_lines.append("")
        details_lines.append("Reason:")
        if bad_reasons:
            details_lines.extend(f"- {r}" for r in bad_reasons)
        else:
            details_lines.append("- Cloudflare SOA serials match SolidServer source serial")

        events.append(
            CheckEvent(
                key=f"dns-soa-sync:{zone}",
                ok=ok,
                severity=severity,
                event_type="dns-soa-sync",
                device=f"external-dns:{zone}",
                summary=f"Cloudflare secondary SOA sync for {zone}",
                details="\n".join(details_lines),
                link=link,
            )
        )

    return events


def build_events() -> list[CheckEvent]:
    events = []
    enabled = env_list("NETOPS_ALERT_ENABLED_CHECKS", ["ntp", "dns-soa-sync"])
    enabled_set = set(enabled)

    if "ntp" in enabled_set:
        events.extend(ntp_events())

    if "dns-soa-sync" in enabled_set:
        events.extend(dns_sync_events())

    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Run NetOps synthetic alert checks.")
    parser.add_argument("--dry-run", action="store_true", help="Print payloads without posting or updating state.")
    args = parser.parse_args()

    broker_url = os.getenv("NETOPS_ALERT_BROKER_URL", DEFAULT_BROKER_URL)
    state_file = os.getenv("NETOPS_ALERT_STATE_FILE", DEFAULT_STATE_FILE)

    print(f"NetOps synthetic alerts starting at {utc_now()}")
    print(f"Broker URL: {broker_url}")
    print(f"State file: {state_file}")

    events = build_events()

    for event in events:
        print(f"CHECK {event.key} ok={event.ok} severity={event.severity}")

    process_events(events, state_file, broker_url, dry_run=args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
