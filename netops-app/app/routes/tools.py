import os

from app.services.dns_dashboard import dns_dashboard_context
from fastapi import Response, APIRouter, Request

from app.core.config import APP_PREFIX
from app.services.component_lookup import component_lookup_context, lookup_hub_context
from app.services.solidserver_tool import solidserver_context
from app.services.mist_tool import mist_context, mist_site_detail_context, mist_switch_detail_context, mist_site_detail_context, mist_switch_detail_context
from app.services.universal_tool import universal_context
from app.services.dns_domain_check import dns_domain_check_context
from app.services.device_page import device_page_context
from app.services.dns_usage import dns_usage_context, dns_usage_csv
from app.services.ntp_dashboard import ntp_dashboard_context
from fastapi.templating import Jinja2Templates
from app.services.time_dns_dashboard import time_dns_dashboard_context


router = APIRouter()
templates = Jinja2Templates(directory="/app/app/templates")



@router.get("/tools/solidserver")
async def solidserver_lookup(request: Request, q: str = "", limit: int = 50, debug: int = 0):
    context = solidserver_context(
        prefix=APP_PREFIX,
        q=q,
        limit=limit,
        show_debug=bool(debug),
    )
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/solidserver.html",
        context=context,
    )




@router.get("/tools/mist")
async def mist_lookup(request: Request, q: str = "", limit: int = 50):
    context = mist_context(q=q, limit=limit)
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/mist.html",
        context=context,
    )


@router.get("/tools/mist/site")
async def mist_site_detail(request: Request, site_id: str, limit: int = 100):
    try:
        context = mist_site_detail_context(site_id=site_id, limit=limit)
        context["request"] = request
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="tools/mist_site.html",
            context=context,
        )
    except Exception as exc:
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="tools/placeholder.html",
            context={
                "request": request,
                "title": "Mist Site Drilldown Error",
                "subtitle": site_id,
                "message": str(exc),
                "next_steps": [
                    "Go back to Mist Overview and retry the site link.",
                    "Check container logs if this persists.",
                ],
            },
        )


@router.get("/tools/mist/switch")
async def mist_switch_detail(request: Request, site_id: str, mac: str):
    try:
        context = mist_switch_detail_context(site_id=site_id, mac=mac)
        context["request"] = request
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="tools/mist_switch.html",
            context=context,
        )
    except Exception as exc:
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="tools/placeholder.html",
            context={
                "request": request,
                "title": "Mist Switch Drilldown Error",
                "subtitle": f"site_id={site_id} mac={mac}",
                "message": str(exc),
                "next_steps": [
                    "Go back to Mist Overview and retry the switch link.",
                    "Confirm the switch is still present in Mist inventory.",
                ],
            },
        )

@router.get("/tools/dns")
async def dns_tools(
    request: Request,
    zone: str = "middlebury.edu",
    host: str = "catalog.middlebury.edu",
    qtype: str = "A",
    cf_ns: str = "ns0245.secondary.cloudflare.com,ns0045.secondary.cloudflare.com",
    parent_servers: str = "a.edu-servers.net,h.edu-servers.net",
    public_resolvers: str = "1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222",
    campus_resolvers: str = "140.233.1.4,140.233.2.204",
):
    context = dns_domain_check_context(
        zone=zone,
        host=host,
        qtype=qtype,
        cf_ns=cf_ns,
        parent_servers=parent_servers,
        public_resolvers=public_resolvers,
        campus_resolvers=campus_resolvers,
    )
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/dns_domain_check.html",
        context=context,
    )


@router.get("/tools/lldp")
async def lldp_lookup_placeholder(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": "LLDP Lookup",
            "subtitle": "Placeholder for v4 LLDP neighbor lookup.",
            "message": "This will become the switch/interface/neighbor lookup tool using LibreNMS LLDP data and eventually Mist switch data.",
            "next_steps": [
                "Search by switch, local port, remote hostname, remote port, chassis ID, or MAC.",
                "Link local devices and interfaces to drilldown pages.",
                "Fold Mist switch LLDP/port data in after Mist standalone lookup works.",
            ],
        },
    )


@router.get("/tools/universal")
async def universal_lookup(request: Request, q: str = "", limit: int = 50):
    context = universal_context(q=q, limit=limit)
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/universal.html",
        context=context,
    )


@router.get("/tools/lookup")
async def lookup_hub(request: Request):
    context = lookup_hub_context(APP_PREFIX)
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/lookup_hub.html",
        context=context,
    )


@router.get("/tools/lookup/{component}")
async def component_lookup(request: Request, component: str, q: str = "", limit: int = 50):
    context = component_lookup_context(
        prefix=APP_PREFIX,
        component=component,
        q=q,
        limit=limit,
    )
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/component_lookup.html",
        context=context,
    )


# --- Top nav placeholder/landing routes v2 ---

@router.get("/dashboards")
async def dashboards_home(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": "Dashboards",
            "subtitle": "NetOps v4 dashboard landing page",
            "message": "Dashboard landing page placeholder. Working operational views are currently under Reports and Tools.",
            "next_steps": ["Use Reports for LibreNMS tables.", "Use Tools for Lookup Hub, Universal Lookup, Mist, SolidServer, and DNS tools."],
        },
    )



@router.get("/dashboards/dns")
async def dns_dashboard(request: Request, zone: str = ""):
    context = dns_dashboard_context(zone=zone or None)
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/dns_dashboard.html",
        context=context,
    )



@router.get("/dashboards/ntp")
async def ntp_dashboard(request: Request):
    context = ntp_dashboard_context()
    context["request"] = request
    return templates.TemplateResponse(request, "tools/ntp_dashboard.html", context)


@router.get("/dashboards/time-dns")
async def time_dns_dashboard(request: Request):
    context = time_dns_dashboard_context()
    context["request"] = request
    return templates.TemplateResponse(request, "tools/time_dns_dashboard.html", context)

@router.get("/dashboards/{page}")
async def dashboards_placeholder(request: Request, page: str):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": f"Dashboard: {page}",
            "subtitle": "Dashboard placeholder",
            "message": "This dashboard route is reserved for a future v4 dashboard.",
            "next_steps": ["No dead link here now.", "Use Reports and Tools for current working pages."],
        },
    )


@router.get("/admin")
async def admin_home(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": "Admin",
            "subtitle": "Admin landing page",
            "message": "Admin placeholder.",
            "next_steps": ["Use /health for raw app health.", "Routes page can be wired later."],
        },
    )


@router.get("/admin/{page}")
async def admin_placeholder(request: Request, page: str):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": f"Admin: {page}",
            "subtitle": "Admin placeholder",
            "message": "Admin route placeholder.",
            "next_steps": ["No dead link here now."],
        },
    )


@router.get("/new")
async def new_home(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": "New",
            "subtitle": "New item landing page",
            "message": "Placeholder for future new report/tool workflows.",
            "next_steps": ["Current feature work is still done in code/Git."],
        },
    )


@router.get("/new/{page}")
async def new_placeholder(request: Request, page: str):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": f"New: {page}",
            "subtitle": "New placeholder",
            "message": "New workflow placeholder.",
            "next_steps": ["No dead link here now."],
        },
    )


@router.get("/pdf")
async def pdf_home(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": "PDF",
            "subtitle": "PDF landing page",
            "message": "PDF export placeholder.",
            "next_steps": ["Use browser print/PDF for now."],
        },
    )


@router.get("/pdf/{page}")
async def pdf_placeholder(request: Request, page: str):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": f"PDF: {page}",
            "subtitle": "PDF placeholder",
            "message": "PDF route placeholder.",
            "next_steps": ["No dead link here now."],
        },
    )

@router.get("/tools/dns")
async def dns_tools(
    request: Request,
    zone: str = "middlebury.edu",
    host: str = "catalog.middlebury.edu",
    qtype: str = "A",
    cf_ns: str = "ns0245.secondary.cloudflare.com,ns0045.secondary.cloudflare.com",
    parent_servers: str = "a.edu-servers.net,h.edu-servers.net",
    public_resolvers: str = "1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222",
    campus_resolvers: str = "140.233.1.4,140.233.2.204",
):
    context = dns_domain_check_context(
        zone=zone,
        host=host,
        qtype=qtype,
        cf_ns=cf_ns,
        parent_servers=parent_servers,
        public_resolvers=public_resolvers,
        campus_resolvers=campus_resolvers,
    )
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/dns_domain_check.html",
        context=context,
    )


@router.get("/dashboards")
async def dashboards_home(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            "Dashboards",
            "NetOps v4 dashboard landing page",
            "Dashboard landing page placeholder. Current working views are under Reports and Tools.",
            ["Use Reports for operational tables.", "Use Tools for Universal Lookup, Mist, SolidServer, and DNS tools."],
        ),
    )


@router.get("/dashboards/{page}")
async def dashboards_page(request: Request, page: str):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            f"Dashboard: {page}",
            "Dashboard placeholder",
            "This dashboard route is reserved for future v4 dashboard work.",
        ),
    )


@router.get("/admin")
async def admin_home(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            "Admin",
            "Admin landing page",
            "Admin placeholder. Use /health for raw app health.",
        ),
    )


@router.get("/admin/{page}")
async def admin_page(request: Request, page: str):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            f"Admin: {page}",
            "Admin placeholder",
            "Admin route placeholder.",
        ),
    )


@router.get("/new")
async def new_home(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            "New",
            "New item landing page",
            "Placeholder for future report/tool creation workflows.",
        ),
    )


@router.get("/new/{page}")
async def new_page(request: Request, page: str):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            f"New: {page}",
            "New placeholder",
            "New workflow placeholder.",
        ),
    )


@router.get("/pdf")
async def pdf_home(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            "PDF",
            "PDF landing page",
            "PDF export placeholder. Use browser print/PDF for now.",
        ),
    )


@router.get("/pdf/{page}")
async def pdf_page(request: Request, page: str):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            f"PDF: {page}",
            "PDF placeholder",
            "PDF route placeholder.",
        ),
    )

@router.get("/tools/dns")
async def dns_tools(
    request: Request,
    zone: str = "middlebury.edu",
    host: str = "catalog.middlebury.edu",
    qtype: str = "A",
    cf_ns: str = "ns0245.secondary.cloudflare.com,ns0045.secondary.cloudflare.com",
    parent_servers: str = "a.edu-servers.net,h.edu-servers.net",
    public_resolvers: str = "1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222",
    campus_resolvers: str = "140.233.1.4,140.233.2.204",
):
    context = dns_domain_check_context(
        zone=zone,
        host=host,
        qtype=qtype,
        cf_ns=cf_ns,
        parent_servers=parent_servers,
        public_resolvers=public_resolvers,
        campus_resolvers=campus_resolvers,
    )
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/dns_domain_check.html",
        context=context,
    )


@router.get("/tools/lldp")
async def lldp_tools(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context=placeholder_context(
            request,
            "LLDP Lookup",
            "LLDP lookup placeholder",
            "LLDP lookup is not fully ported to v4 yet.",
            ["Use Interface Lookup or Universal Lookup for now."],
        ),
    )


@router.get("/tools/device/{device_id}")
async def midd_device_page(request: Request, device_id: int):
    context = device_page_context(device_id)
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/device_page.html",
        context=context,
    )




@router.get("/tools/dns-usage.csv")
async def dns_usage_csv_page(request: Request, q: str = "", limit_zones: int = 5000, limit_rr: int = 100000):
    context = dns_usage_context(
        q=q,
        limit_zones=max(100, min(int(limit_zones or 5000), 20000)),
        limit_rr=max(1000, min(int(limit_rr or 100000), 500000)),
    )
    csv_text = dns_usage_csv(context)
    filename = "dns-external-zone-usage.csv"
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@router.get("/tools/dns-usage")
async def dns_usage_page(request: Request, q: str = "", limit_zones: int = 5000, limit_rr: int = 100000):
    context = dns_usage_context(
        q=q,
        limit_zones=max(100, min(int(limit_zones or 5000), 20000)),
        limit_rr=max(1000, min(int(limit_rr or 100000), 500000)),
    )
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/dns_usage.html",
        context=context,
    )

