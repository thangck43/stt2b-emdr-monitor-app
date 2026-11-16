"""DLP Monitor - backend giám sát đăng nhập portal & kiểm soát download.

Chạy:  uvicorn app.main:app --host 0.0.0.0 --port 8080
"""
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .config import Settings, settings as default_settings
from .db import Database, now_iso
from .notifier import notify
from .policy import evaluate_download

STATIC_DIR = Path(__file__).parent / "static"

EVENT_TYPES = {"login", "logout", "visit", "login_failed", "agent_tamper", "agent_heartbeat"}


# ---------- Schemas ----------
class DownloadCheck(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    url: str = ""
    filename: str = ""
    size_bytes: int = 0
    mime: str = ""
    device: str = ""


class AgentEvent(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    type: str
    url: str = ""
    device: str = ""
    detail: str = ""


class UserPolicy(BaseModel):
    display_name: str | None = None
    department: str | None = None
    download_allowed: bool | None = None
    allowed_extensions: str | None = None
    max_size_mb: float | None = None
    allow_until: str | None = None
    login_allowed: bool | None = None
    note: str | None = None


class AckBody(BaseModel):
    by: str = "admin"


def norm_user(u: str) -> str:
    return u.strip().lower()


def create_app(cfg: Settings | None = None) -> FastAPI:
    cfg = cfg or default_settings
    db = Database(cfg.db_path)
    app = FastAPI(title="DLP Portal Monitor", version="1.0.0")
    app.state.db = db
    app.state.settings = cfg

    # Extension gọi từ origin chrome-extension://...
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---------- auth ----------
    def require_agent(x_agent_key: str = Header(default="")) -> None:
        if not secrets.compare_digest(x_agent_key, cfg.agent_key):
            raise HTTPException(401, "Agent key không hợp lệ")

    def require_admin(authorization: str = Header(default="")) -> None:
        token = authorization.removeprefix("Bearer ").strip()
        if not secrets.compare_digest(token, cfg.admin_token):
            raise HTTPException(401, "Admin token không hợp lệ")

    # ---------- helpers ----------
    def ensure_user(username: str) -> tuple[dict | None, bool]:
        user = db.get_user(username)
        if user is None and cfg.auto_register_users:
            user = db.upsert_user(
                username, download_allowed=int(cfg.default_download_allowed),
                note="Tự đăng ký khi phát hiện lần đầu",
            )
            return user, True
        return user, False

    def raise_alert(username: str, severity: str, kind: str, message: str,
                    event_id: int | None = None) -> None:
        db.add_alert(username, severity, kind, message, event_id)
        notify(cfg, severity, username, message)

    def client_ip(req: Request) -> str:
        fwd = req.headers.get("x-forwarded-for", "")
        return fwd.split(",")[0].strip() if fwd else (req.client.host if req.client else "")

    def recent_blocked(username: str, minutes: int = 10) -> int:
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
        row = db.one(
            "SELECT COUNT(*) AS n FROM events WHERE username = ? AND type = 'download_blocked' AND ts >= ?",
            (username, since),
        )
        return int(row["n"]) if row else 0

    def handle_download(username: str, url: str, filename: str, size: int,
                        ip: str, device: str, source: str, mime: str = "") -> dict:
        user, created = ensure_user(username)
        decision = evaluate_download(user, filename, size, cfg)
        etype = "download_allowed" if decision.allowed else "download_blocked"
        eid = db.add_event(
            username=username, type=etype, url=url[:2000], filename=filename[:500],
            size_bytes=size, ip=ip, device=device, source=source,
            detail=f"{decision.reason}" + (f" | mime={mime}" if mime else ""),
        )
        if not decision.allowed:
            n = recent_blocked(username)
            sev = "high" if n >= cfg.burst_threshold else "medium"
            msg = f"Chặn download '{filename or url}' - {decision.reason}"
            if sev == "high":
                msg += f" (đã bị chặn {n} lần trong 10 phút)"
            raise_alert(username, sev, "download_blocked", msg, eid)
        if created:
            raise_alert(username, "low", "new_user", "Phát hiện user mới truy cập portal", eid)
        return {"allowed": decision.allowed, "reason": decision.reason, "event_id": eid}

    # ---------- Agent API (extension / gateway) ----------
    @app.post("/api/agent/check-download", dependencies=[Depends(require_agent)])
    def check_download(body: DownloadCheck, request: Request):
        return handle_download(
            norm_user(body.username), body.url, body.filename, max(body.size_bytes, 0),
            client_ip(request), body.device, "extension", body.mime,
        )

    @app.post("/api/agent/event", dependencies=[Depends(require_agent)])
    def agent_event(body: AgentEvent, request: Request):
        if body.type not in EVENT_TYPES:
            raise HTTPException(400, f"type phải thuộc {sorted(EVENT_TYPES)}")
        username = norm_user(body.username)
        user, created = ensure_user(username)
        eid = db.add_event(
            username=username, type=body.type, url=body.url[:2000], ip=client_ip(request),
            device=body.device, source="extension", detail=body.detail[:1000],
        )
        if body.type == "login":
            if created:
                raise_alert(username, "low", "new_user", "User mới đăng nhập portal lần đầu", eid)
            if user is not None and not user.get("login_allowed", 1):
                raise_alert(username, "high", "blocked_user_login",
                            "User đã bị khóa nhưng vẫn đăng nhập portal", eid)
            hour = datetime.now().hour
            if not (cfg.work_hour_start <= hour < cfg.work_hour_end):
                raise_alert(username, "medium", "off_hours_login",
                            f"Đăng nhập ngoài giờ làm việc ({hour}h)", eid)
        elif body.type == "login_failed":
            since = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec="seconds")
            n = db.one("SELECT COUNT(*) AS n FROM events WHERE username=? AND type='login_failed' AND ts>=?",
                       (username, since))["n"]
            if n >= 5:
                raise_alert(username, "high", "brute_force", f"{n} lần đăng nhập thất bại trong 10 phút", eid)
        elif body.type == "agent_tamper":
            raise_alert(username, "high", "agent_tamper",
                        f"Phát hiện can thiệp vào agent giám sát: {body.detail}", eid)
        return {"ok": True, "event_id": eid}

    @app.get("/api/agent/policy", dependencies=[Depends(require_agent)])
    def agent_policy(username: str):
        user = db.get_user(norm_user(username))
        if user is None:
            return {"username": norm_user(username), "download_allowed": cfg.default_download_allowed,
                    "login_allowed": True}
        return {k: user[k] for k in ("username", "download_allowed", "allowed_extensions",
                                     "max_size_mb", "allow_until", "login_allowed")}

    # ---------- Gateway (nginx auth_request) cho portal tự quản ----------
    dl_pattern = re.compile(os.getenv(
        "DLP_GATEWAY_DOWNLOAD_PATTERN",
        r"(/download|/export|/attachment|\.(pdf|docx?|xlsx?|csv|zip|rar|7z|pptx?|txt|json|xml)(\?|$))",
    ), re.IGNORECASE)
    login_pattern = re.compile(os.getenv("DLP_GATEWAY_LOGIN_PATTERN", r"/(login|signin|auth)"), re.IGNORECASE)

    @app.get("/api/gate", dependencies=[Depends(require_agent)])
    def gate(request: Request,
             x_portal_user: str = Header(default=""),
             x_original_uri: str = Header(default=""),
             x_original_method: str = Header(default="GET")):
        """Nginx gọi endpoint này trước mỗi request tới portal. 204 = cho qua, 403 = chặn."""
        username = norm_user(x_portal_user) or "anonymous"
        ip = client_ip(request)
        path = x_original_uri.split("?", 1)[0]
        if login_pattern.search(path) and x_original_method.upper() == "POST":
            db.add_event(username=username, type="login", url=x_original_uri, ip=ip, source="gateway")
            return Response(status_code=204)
        if dl_pattern.search(x_original_uri):
            filename = path.rsplit("/", 1)[-1]
            result = handle_download(username, x_original_uri, filename, 0, ip, "", "gateway")
            return Response(status_code=204 if result["allowed"] else 403)
        return Response(status_code=204)

    # ---------- Admin API ----------
    @app.get("/api/admin/users", dependencies=[Depends(require_admin)])
    def list_users():
        return db.query("SELECT * FROM users ORDER BY username")

    @app.put("/api/admin/users/{username}", dependencies=[Depends(require_admin)])
    def put_user(username: str, body: UserPolicy):
        fields = {k: (int(v) if isinstance(v, bool) else v)
                  for k, v in body.model_dump().items() if v is not None}
        if "allow_until" in fields and fields["allow_until"]:
            try:
                datetime.fromisoformat(fields["allow_until"])
            except ValueError:
                raise HTTPException(400, "allow_until phải là ISO datetime, vd 2026-12-31T18:00:00+07:00")
        return db.upsert_user(norm_user(username), **fields)

    @app.delete("/api/admin/users/{username}", dependencies=[Depends(require_admin)])
    def del_user(username: str):
        db.delete_user(norm_user(username))
        return {"ok": True}

    @app.get("/api/admin/events", dependencies=[Depends(require_admin)])
    def list_events(username: str = "", type: str = "", limit: int = Query(200, le=2000)):
        sql, params = "SELECT * FROM events WHERE 1=1", []
        if username:
            sql += " AND username = ?"
            params.append(norm_user(username))
        if type:
            sql += " AND type = ?"
            params.append(type)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return db.query(sql, params)

    @app.get("/api/admin/alerts", dependencies=[Depends(require_admin)])
    def list_alerts(only_open: bool = False, limit: int = Query(200, le=2000)):
        sql = "SELECT * FROM alerts" + (" WHERE acknowledged = 0" if only_open else "")
        return db.query(sql + " ORDER BY id DESC LIMIT ?", (limit,))

    @app.post("/api/admin/alerts/{alert_id}/ack", dependencies=[Depends(require_admin)])
    def ack_alert(alert_id: int, body: AckBody):
        with db.tx() as c:
            c.execute("UPDATE alerts SET acknowledged=1, ack_by=?, ack_at=? WHERE id=?",
                      (body.by, now_iso(), alert_id))
        return {"ok": True}

    @app.get("/api/admin/stats", dependencies=[Depends(require_admin)])
    def stats():
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
        counts = {r["type"]: r["n"] for r in db.query(
            "SELECT type, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY type", (since,))}
        online = db.query(
            "SELECT username, MAX(ts) AS last_seen FROM events WHERE ts >= ? GROUP BY username "
            "ORDER BY last_seen DESC", (since,))
        top_blocked = db.query(
            "SELECT username, COUNT(*) AS n FROM events WHERE type='download_blocked' AND ts >= ? "
            "GROUP BY username ORDER BY n DESC LIMIT 10", (since,))
        open_alerts = db.one("SELECT COUNT(*) AS n FROM alerts WHERE acknowledged=0")["n"]
        return {"last_24h": counts, "active_users": online, "top_blocked": top_blocked,
                "open_alerts": open_alerts}

    @app.get("/healthz")
    def health():
        return {"ok": True}

    @app.get("/")
    def dashboard():
        return FileResponse(STATIC_DIR / "dashboard.html")

    return app


app = create_app()
