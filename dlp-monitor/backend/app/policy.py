"""Quyết định cho phép / chặn download theo policy của từng user."""
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import Settings


@dataclass
class Decision:
    allowed: bool
    reason: str


def _ext(filename: str) -> str:
    name = (filename or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def evaluate_download(user: dict | None, filename: str, size_bytes: int,
                      settings: Settings, now: datetime | None = None) -> Decision:
    now = now or datetime.now(timezone.utc)

    if user is None:
        if settings.default_download_allowed:
            return Decision(True, "Chưa có policy riêng - mặc định cho phép")
        return Decision(False, "User chưa được cấp quyền download")

    if not user.get("login_allowed", 1):
        return Decision(False, "User đang bị khóa truy cập portal")

    if not user.get("download_allowed"):
        return Decision(False, "User không được phép download")

    until = (user.get("allow_until") or "").strip()
    if until:
        try:
            exp = datetime.fromisoformat(until)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now > exp:
                return Decision(False, f"Quyền download đã hết hạn ({until})")
        except ValueError:
            return Decision(False, "Cấu hình allow_until không hợp lệ")

    exts = [x.strip().lower().lstrip(".") for x in (user.get("allowed_extensions") or "").split(",") if x.strip()]
    if exts:
        e = _ext(filename)
        if e not in exts:
            return Decision(False, f"Loại file '.{e or '?'}' không nằm trong danh sách cho phép ({', '.join(exts)})")

    max_mb = float(user.get("max_size_mb") or 0)
    if max_mb > 0 and size_bytes and size_bytes > max_mb * 1024 * 1024:
        return Decision(False, f"File vượt quá giới hạn {max_mb:g} MB")

    return Decision(True, "Được phép theo policy")
