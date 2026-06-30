from fastapi import APIRouter, Request

from app.core.config import APP_PREFIX
from app.services.component_lookup import component_lookup_context, lookup_hub_context


router = APIRouter()


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
