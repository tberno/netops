import os
from typing import Any

import pymysql


def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value not in (None, ""):
            return value
    return default


def db_conn():
    return pymysql.connect(
        host=_env("LIBRENMS_DB_HOST", "MYSQL_HOST", "DB_HOST", default="127.0.0.1"),
        port=int(_env("LIBRENMS_DB_PORT", "MYSQL_PORT", "DB_PORT", default="3306")),
        user=_env("LIBRENMS_DB_USER", "MYSQL_USER", "DB_USER", default="librenms"),
        password=_env("LIBRENMS_DB_PASSWORD", "MYSQL_PASSWORD", "DB_PASSWORD", default=""),
        database=_env("LIBRENMS_DB_NAME", "MYSQL_DATABASE", "DB_DATABASE", default="librenms"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())
