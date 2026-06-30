import os

from fastapi import APIRouter, Request

from app.core.config import APP_PREFIX
from app.services.component_lookup import component_lookup_context, lookup_hub_context
from app.services.solidserver_tool import solidserver_context
from app.services.mist_tool import mist_context, mist_site_detail_context, mist_switch_detail_context, mist_site_detail_context, mist_switch_detail_context
from app.services.universal_tool import universal_context


router = APIRouter()



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
async def dns_tools_placeholder(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": "DNS Tools",
            "subtitle": "Placeholder for v4 DNS checks.",
            "message": "This will become the DNS resolver, record, delegation, SOA/serial, and Cloudflare secondary validation tool.",
            "next_steps": [
                "Port the known-good v3 DNS lookup tools.",
                "Add resolver selector for Hera, Zeus, Cloudflare, Google, Quad9.",
                "Add record checks for A, AAAA, CNAME, MX, NS, SOA, TXT, PTR.",
                "Add zone serial and secondary sync checks.",
            ],
        },
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
async def dns_tools_placeholder(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": "DNS Tools",
            "subtitle": "DNS tools placeholder",
            "message": "DNS tools are not fully ported to v4 yet.",
            "next_steps": ["Use Universal Lookup or SolidServer DDI for now.", "Port v3 DNS tools next."],
        },
    )
