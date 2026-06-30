import csv
import html as html_lib
import io
import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from app.core.config import APP_PREFIX
from app.services.interface_config import interface_configuration_context
from app.services.interface_stats import interface_statistics_context
from app.services.mac_table import mac_table_context
from app.services.arp_ip import arp_ip_context
from app.services.vlans import vlans_context
from app.services.unused_interfaces import unused_interfaces_context
from app.services.events import events_context


router = APIRouter()


TAG_RE = re.compile(r"<[^>]+>")


def plain(value: Any) -> str:
    text = "" if value is None else str(value)
    text = TAG_RE.sub("", text)
    return html_lib.unescape(text).strip()


def csv_response(context: dict[str, Any], filename: str) -> StreamingResponse:
    output = io.StringIO()
    writer = csv.writer(output)

    columns = context["columns"]
    rows = context["rows"]

    writer.writerow([col["label"] for col in columns])

    for row in rows:
        writer.writerow([plain(row.get(col["key"], "")) for col in columns])

    data = output.getvalue()
    output.close()

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }

    return StreamingResponse(
        iter([data]),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )


@router.get("/reports/interface-statistics")
async def interface_statistics(request: Request, q: str = "", device_ids: str = "", limit: int = 150):
    context = interface_statistics_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    context["request"] = request
    context["active"] = "reports"
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="reports/interface_stats.html",
        context=context,
    )


@router.get("/reports/interface-statistics.csv")
async def interface_statistics_csv(q: str = "", device_ids: str = "", limit: int = 150):
    context = interface_statistics_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    return csv_response(context, "interface-statistics.csv")


@router.get("/reports/interface-configuration")
async def interface_configuration(request: Request, q: str = "", device_ids: str = "", limit: int = 150):
    context = interface_configuration_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    context["request"] = request
    context["active"] = "reports"
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="reports/interface_config.html",
        context=context,
    )


@router.get("/reports/interface-configuration.csv")
async def interface_configuration_csv(q: str = "", device_ids: str = "", limit: int = 150):
    context = interface_configuration_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    return csv_response(context, "interface-configuration.csv")


@router.get("/reports/mac-table")
async def mac_table(request: Request, q: str = "", device_ids: str = "", limit: int = 1000):
    context = mac_table_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    context["request"] = request
    context["active"] = "reports"
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="reports/mac_table.html",
        context=context,
    )


@router.get("/reports/mac-table.csv")
async def mac_table_csv(q: str = "", device_ids: str = "", limit: int = 1000):
    context = mac_table_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    return csv_response(context, "mac-table.csv")


@router.get("/reports/arp-ip")
async def arp_ip(request: Request, q: str = "", device_ids: str = "", limit: int = 500):
    context = arp_ip_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    context["request"] = request
    context["active"] = "reports"
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="reports/arp_ip.html",
        context=context,
    )


@router.get("/reports/arp-ip.csv")
async def arp_ip_csv(q: str = "", device_ids: str = "", limit: int = 500):
    context = arp_ip_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    return csv_response(context, "arp-ip.csv")


@router.get("/reports/vlans")
async def vlans(request: Request, q: str = "", device_ids: str = "", limit: int = 500):
    context = vlans_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    context["request"] = request
    context["active"] = "reports"
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="reports/vlans.html",
        context=context,
    )


@router.get("/reports/vlans.csv")
async def vlans_csv(q: str = "", device_ids: str = "", limit: int = 500):
    context = vlans_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    return csv_response(context, "vlans.csv")


@router.get("/reports/unused-interfaces")
async def unused_interfaces(request: Request, q: str = "", device_ids: str = "", limit: int = 500):
    context = unused_interfaces_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    context["request"] = request
    context["active"] = "reports"
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="reports/unused_interfaces.html",
        context=context,
    )


@router.get("/reports/unused-interfaces.csv")
async def unused_interfaces_csv(q: str = "", device_ids: str = "", limit: int = 500):
    context = unused_interfaces_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    return csv_response(context, "unused-interfaces.csv")


@router.get("/reports/events")
async def events(request: Request, q: str = "", device_ids: str = "", limit: int = 500):
    context = events_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    context["request"] = request
    context["active"] = "reports"
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="reports/events.html",
        context=context,
    )


@router.get("/reports/events.csv")
async def events_csv(q: str = "", device_ids: str = "", limit: int = 500):
    context = events_context(
        prefix=APP_PREFIX,
        q=q,
        device_ids=device_ids,
        limit=limit,
    )
    return csv_response(context, "events.csv")
