"""DLP Monitor - backend giám sát đăng nhập portal & kiểm soát download.

Chạy:  uvicorn app.main:app --host 0.0.0.0 --port 8080
"""
import fnmatch
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
from .notifier import email_user, notify
from .policy import evaluate_download

STATIC_DIR = Path(__file__).parent / "static"

EVENT_TYPES = {"login", "logout", "visit", "login_failed", "agent_tamper", "agent_heartbeat", "warning_ack"}


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
    portal_username: str = Field(default="", max_length=200)  # tên user gõ vào form login portal
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


class WatchEntry(BaseModel):
    reason: str | None = None
    warn_message: str | None = None
    notify_email: str | None = None
    severity: str | None = Field(default=None, pattern="^(low|medium|high)$")
    enabled: bool | None = None


class WatchBulk(BaseModel):
    # Dán danh sách: mỗi dòng / dấu phẩy / dấu chấm phẩy là một username hoặc pattern
    usernames: str
    reason: str = ""
    warn_message: str = ""
    severity: str = Field(default="high", pattern="^(low|medium|high)$")
    replace: bool = False  # true = xóa danh sách cũ trước khi nhập


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

    # ---------- Watchlist ----------
    def match_watchlist(*names: str) -> tuple[dict, str] | None:
        """Trả về (entry, tên khớp) nếu một trong các tên nằm trong watchlist (hỗ trợ wildcard * ?)."""
        cands = [norm_user(n) for n in names if n and n.strip()]
        if not cands:
            return None
        for entry in db.query("SELECT * FROM watchlist WHERE enabled = 1"):
            pat = entry["pattern"]
            for n in cands:
                if n == pat or fnmatch.fnmatchcase(n, pat):
                    return entry, n
        return None

    def handle_watchlist(username: str, portal_username: str, url: str, ip: str, device: str,
                         source: str, trigger: str) -> dict | None:
        """Ghi log + cảnh báo admin + email user khi user trong watchlist đăng nhập/truy cập portal.
        Trả về nội dung warning để agent hiển thị cho user."""
        hit = match_watchlist(username, portal_username)
        if not hit:
            return None
        entry, matched = hit
        message = entry["warn_message"] or cfg.default_warning
        eid = db.add_event(
            username=username, type="watchlist_hit", url=url[:2000], ip=ip, device=device, source=source,
            detail=f"trigger={trigger}; khớp '{entry['pattern']}' (tên: {matched}); lý do: {entry['reason']}"[:1000],
        )
        since = (datetime.now(timezone.utc) - timedelta(minutes=cfg.watchlist_alert_dedupe_minutes)).isoformat(timespec="seconds")
        recent = db.one("SELECT id FROM alerts WHERE username = ? AND kind = 'watchlist_login' AND ts >= ?",
                        (username, since))
        if trigger == "login" or recent is None:
            who = username + (f" (portal: {portal_username})" if portal_username and norm_user(portal_username) != username else "")
            raise_alert(username, entry["severity"], "watchlist_login",
                        f"User trong danh sách theo dõi {'đăng nhập' if trigger == 'login' else 'truy cập'} portal: "
                        f"{who} từ IP {ip or '?'}" + (f" – lý do: {entry['reason']}" if entry["reason"] else ""), eid)
            to = entry["notify_email"] or next((n for n in (username, portal_username) if "@" in (n or "")), "")
            if email_user(cfg, to, "[Cảnh báo bảo mật] Phiên đăng nhập portal của bạn đang được giám sát",
                          f"Xin chào {portal_username or username},\n\n{message}\n\n"
                          f"Thời điểm: {now_iso()} (UTC)\nĐịa chỉ: {url}\nIP: {ip}\n\n"
                          "Nếu không phải bạn đăng nhập, hãy báo ngay cho bộ phận IT."):
                db.add_event(username=username, type="warning_email", detail=f"Đã gửi email cảnh báo tới {to}",
                             source=source)
        return {"title": "Cảnh báo bảo mật", "message": message, "event_id": eid}

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
        ip = client_ip(request)
        detail = body.detail[:1000]
        if body.portal_username and f"portal_username={body.portal_username}" not in detail:
            detail = (f"portal_username={body.portal_username[:200]} " + detail).strip()
        eid = db.add_event(
            username=username, type=body.type, url=body.url[:2000], ip=ip,
            device=body.device, source="extension", detail=detail,
        )
        warning = None
        if body.type in ("login", "visit"):
            warning = handle_watchlist(username, body.portal_username, body.url, ip, body.device,
                                       "extension", body.type)
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
        return {"ok": True, "event_id": eid, "warning": warning}

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
            handle_watchlist(username, "", x_original_uri, ip, "", "gateway", "login")
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

    @app.get("/api/admin/watchlist", dependencies=[Depends(require_admin)])
    def list_watch():
        rows = db.query("SELECT * FROM watchlist ORDER BY pattern")
        since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
        hits = db.query("SELECT detail, ts FROM events WHERE type='watchlist_hit' AND ts >= ? ORDER BY id", (since,))
        for r in rows:
            mine = [h for h in hits if f"khớp '{r['pattern']}'" in h["detail"]]
            r["hits_30d"] = len(mine)
            r["last_hit"] = mine[-1]["ts"] if mine else ""
        return rows

    def upsert_watch(pattern: str, fields: dict) -> None:
        ts = now_iso()
        with db.tx() as c:
            c.execute("INSERT OR IGNORE INTO watchlist (pattern, created_at, updated_at) VALUES (?, ?, ?)",
                      (pattern, ts, ts))
            if fields:
                cols = ", ".join(f"{k} = ?" for k in fields)
                c.execute(f"UPDATE watchlist SET {cols}, updated_at = ? WHERE pattern = ?",
                          (*fields.values(), ts, pattern))

    @app.put("/api/admin/watchlist/{pattern}", dependencies=[Depends(require_admin)])
    def put_watch(pattern: str, body: WatchEntry):
        p = norm_user(pattern)
        if not p:
            raise HTTPException(400, "pattern rỗng")
        upsert_watch(p, {k: (int(v) if isinstance(v, bool) else v)
                         for k, v in body.model_dump().items() if v is not None})
        return db.one("SELECT * FROM watchlist WHERE pattern = ?", (p,))

    @app.post("/api/admin/watchlist/bulk", dependencies=[Depends(require_admin)])
    def bulk_watch(body: WatchBulk):
        names = sorted({norm_user(x) for x in re.split(r"[\s,;]+", body.usernames) if x.strip()})
        if body.replace:
            with db.tx() as c:
                c.execute("DELETE FROM watchlist")
        for n in names:
            upsert_watch(n, {"reason": body.reason, "warn_message": body.warn_message,
                             "severity": body.severity, "enabled": 1})
        return {"ok": True, "count": len(names)}

    @app.delete("/api/admin/watchlist/{pattern}", dependencies=[Depends(require_admin)])
    def del_watch(pattern: str):
        with db.tx() as c:
            c.execute("DELETE FROM watchlist WHERE pattern = ?", (norm_user(pattern),))
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
