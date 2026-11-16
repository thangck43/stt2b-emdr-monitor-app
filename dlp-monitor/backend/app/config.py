"""Cấu hình đọc từ biến môi trường."""
import os


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self) -> None:
        self.db_path = os.getenv("DLP_DB_PATH", "dlp_monitor.db")
        # Khóa mà extension/gateway dùng để gọi API agent
        self.agent_key = os.getenv("DLP_AGENT_KEY", "change-me-agent-key")
        # Token cho admin dashboard / admin API
        self.admin_token = os.getenv("DLP_ADMIN_TOKEN", "change-me-admin-token")
        # User chưa có trong danh sách: mặc định CẤM download
        self.default_download_allowed = _bool("DLP_DEFAULT_DOWNLOAD_ALLOWED", False)
        # Tự tạo user khi thấy lần đầu (với quyền mặc định)
        self.auto_register_users = _bool("DLP_AUTO_REGISTER_USERS", True)
        # Webhook cảnh báo (Slack / MS Teams / Google Chat - nhận JSON {"text": ...})
        self.alert_webhook_url = os.getenv("DLP_ALERT_WEBHOOK_URL", "")
        # Telegram (tùy chọn)
        self.telegram_bot_token = os.getenv("DLP_TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.getenv("DLP_TELEGRAM_CHAT_ID", "")
        # Ngưỡng: số lần bị chặn trong 10 phút để nâng cảnh báo lên HIGH
        self.burst_threshold = int(os.getenv("DLP_BURST_THRESHOLD", "3"))
        # Login ngoài giờ làm việc (giờ local server) => cảnh báo
        self.work_hour_start = int(os.getenv("DLP_WORK_HOUR_START", "7"))
        self.work_hour_end = int(os.getenv("DLP_WORK_HOUR_END", "19"))
        # Cảnh báo hiển thị cho user nằm trong watchlist khi đăng nhập portal
        self.default_warning = os.getenv(
            "DLP_DEFAULT_WARNING",
            "Tài khoản của bạn nằm trong danh sách giám sát đặc biệt. Mọi thao tác trên portal "
            "đang được ghi nhận. Không tải xuống, sao chép hay chia sẻ dữ liệu khi chưa được phép.",
        )
        # Không lặp lại cảnh báo admin cho cùng user trong khoảng này (phút)
        self.watchlist_alert_dedupe_minutes = int(os.getenv("DLP_WATCHLIST_DEDUPE_MINUTES", "30"))
        # SMTP để gửi email cảnh báo cho user (tùy chọn)
        self.smtp_host = os.getenv("DLP_SMTP_HOST", "")
        self.smtp_port = int(os.getenv("DLP_SMTP_PORT", "587"))
        self.smtp_user = os.getenv("DLP_SMTP_USER", "")
        self.smtp_password = os.getenv("DLP_SMTP_PASSWORD", "")
        self.smtp_from = os.getenv("DLP_SMTP_FROM", "")
        self.smtp_starttls = _bool("DLP_SMTP_STARTTLS", True)


settings = Settings()
