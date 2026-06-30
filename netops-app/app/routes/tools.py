import os

from fastapi import APIRouter, Request

from app.core.config import APP_PREFIX
from app.services.component_lookup import component_lookup_context, lookup_hub_context
from app.services.solidserver_tool import solidserver_context


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
async def mist_lookup(request: Request):
    context = {
        "request": request,
        "base_url_set": bool(os.environ.get("MIST_BASE_URL", "").strip()),
        "org_id_set": bool(os.environ.get("MIST_ORG_ID", "").strip()),
        "token_set": bool(os.environ.get("MIST_API_TOKEN", "").strip()),
    }
    context["configured"] = context["base_url_set"] and context["org_id_set"] and context["token_set"]
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/mist.html",
        context=context,
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
async def universal_lookup_placeholder(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="tools/placeholder.html",
        context={
            "request": request,
            "title": "Universal Lookup",
            "subtitle": "Placeholder for final combined lookup.",
            "message": "Universal Lookup will be built after all standalone components are stable.",
            "next_steps": [
                "Keep LibreNMS component lookups working.",
                "Keep SolidServer standalone lookup working.",
                "Add Mist standalone lookup after the API token is available.",
                "Then combine LibreNMS, SolidServer, Mist, DNS, LLDP, and events into one safe wrapper.",
            ],
        },
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
