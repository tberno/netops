import os

APP_PREFIX = os.getenv("APP_ROOT_PATH", "/netops-v4").rstrip("/") or "/netops-v4"
PORTAL_NAME = os.getenv("PORTAL_NAME", "NetOps v4")
