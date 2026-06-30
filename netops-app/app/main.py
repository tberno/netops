from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.core.config import APP_PREFIX, PORTAL_NAME
from app.routes.reports import router as reports_router
from app.routes.device import router as device_router
from app.routes.tools import router as tools_router


APP_DIR = Path(__file__).resolve().parent

app = FastAPI(title=PORTAL_NAME)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")

templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
app.state.templates = templates


@app.middleware("http")
async def add_template_globals(request: Request, call_next):
    request.state.app_prefix = APP_PREFIX
    request.state.portal_name = PORTAL_NAME
    return await call_next(request)


@app.get("/")
async def root():
    return RedirectResponse("reports/interface-statistics")


@app.get("/health")
async def health():
    return {"ok": True, "portal": PORTAL_NAME}


app.include_router(reports_router)
app.include_router(device_router)
app.include_router(tools_router)
