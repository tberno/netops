from fastapi import APIRouter, Request

from app.core.config import APP_PREFIX
from app.services.device_detail import device_context, interface_context


router = APIRouter()


@router.get("/device/{device_id}")
async def device_detail(request: Request, device_id: int):
    context = device_context(APP_PREFIX, device_id)
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="device/detail.html",
        context=context,
    )


@router.get("/interface/{port_id}")
async def interface_detail(request: Request, port_id: int):
    context = interface_context(APP_PREFIX, port_id)
    context["request"] = request
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="device/interface.html",
        context=context,
    )
