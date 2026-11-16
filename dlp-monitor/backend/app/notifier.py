"""Gửi cảnh báo ra ngoài (webhook Slack/Teams/Google Chat, Telegram) - không chặn request."""
import json
import logging
import threading
import urllib.parse
import urllib.request

from .config import Settings

log = logging.getLogger("dlp.notifier")

SEVERITY_ICON = {"low": "ℹ️", "medium": "⚠️", "high": "🚨"}


def _post(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as exc:  # không để lỗi notify làm hỏng luồng chính
        log.warning("Gửi cảnh báo thất bại tới %s: %s", urllib.parse.urlsplit(url).netloc, exc)


def notify(settings: Settings, severity: str, username: str, message: str) -> None:
    text = f"{SEVERITY_ICON.get(severity, '')} [DLP {severity.upper()}] {username}: {message}"
    targets: list[tuple[str, dict]] = []
    if settings.alert_webhook_url:
        targets.append((settings.alert_webhook_url, {"text": text}))
    if settings.telegram_bot_token and settings.telegram_chat_id:
        targets.append((
            f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
            {"chat_id": settings.telegram_chat_id, "text": text},
        ))
    for url, payload in targets:
        threading.Thread(target=_post, args=(url, payload), daemon=True).start()
