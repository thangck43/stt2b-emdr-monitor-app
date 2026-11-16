# DLP Portal Monitor

Hệ thống giám sát nhân viên đăng nhập vào portal (vd: Shell DEP) và **chặn download** khi user chưa được cấp quyền. Có cảnh báo realtime cho bộ phận IT/Security.

```
 Máy nhân viên (Chrome/Edge do IT quản lý)              Máy chủ công ty
┌──────────────────────────────────────────┐        ┌──────────────────────────────┐
│ Portal DLP Agent (extension, cài bắt buộc) │  HTTPS │ DLP Backend (FastAPI+SQLite) │
│  • phát hiện login / logout / truy cập     │ ─────▶ │  • policy theo từng user      │
│  • giữ download lại, hỏi server cho/chặn   │ ◀───── │  • log sự kiện, cảnh báo      │
│  • chặn Ctrl+S / Ctrl+P trên portal        │        │  • dashboard quản trị         │
└──────────────────────────────────────────┘        │  • webhook Slack/Teams/Telegram│
                                                     └──────────────────────────────┘
 (Tùy chọn, nếu portal do công ty tự vận hành)                    ▲
 User ──▶ Nginx gateway ──auth_request──▶ /api/gate ──────────────┘
                 └──▶ Portal (chỉ cho qua download được phép)
```

## Hai chế độ triển khai

| | **A. Browser extension** (mặc định) | **B. Nginx gateway** |
|---|---|---|
| Dùng khi | Portal là của bên thứ ba (Shell, đối tác…) – không sửa được | Portal do công ty tự vận hành / đặt được reverse proxy |
| Chặn ở đâu | Trình duyệt trên máy công ty, trước khi file ghi xuống đĩa | Server, trả 403 trước khi file rời portal |
| Điều kiện | Máy do IT quản lý (GPO / Intune / Google Admin) | User đăng nhập qua SSO để biết danh tính |

Có thể dùng **cả hai** cùng lúc; mọi sự kiện đều đổ về chung một dashboard.

## Thành phần

```
dlp-monitor/
├── backend/                  # API + dashboard
│   ├── app/main.py           # endpoints agent, gateway, admin
│   ├── app/policy.py         # luật cho phép/chặn download
│   ├── app/notifier.py       # gửi cảnh báo webhook / Telegram
│   ├── app/static/dashboard.html
│   └── tests/test_api.py
├── extension/                # Chrome/Edge extension (Manifest V3)
├── deploy/
│   ├── nginx-gateway.conf    # chế độ B
│   └── policies/             # GPO .reg cho Chrome/Edge, JSON cho Intune/Google Admin
└── docker-compose.yml
```

## Chính sách download (cấu hình trên dashboard, theo từng user)

- **Mặc định cấm**: user chưa có trong danh sách sẽ bị chặn (`DLP_DEFAULT_DOWNLOAD_ALLOWED=false`).
- Cho phép / cấm download.
- Giới hạn **đuôi file** (vd chỉ `pdf,xlsx`).
- Giới hạn **dung lượng** (MB).
- **Quyền tạm thời**: cấp quyền đến một thời điểm, tự hết hạn.
- **Khóa truy cập**: user bị khóa vẫn đăng nhập portal => cảnh báo HIGH.

## Danh sách theo dõi (watchlist)

Tab **Danh sách theo dõi** trên dashboard: dán danh sách tên đăng nhập (mỗi dòng một tên, hỗ trợ wildcard `*@nhathau.com`, `tmp_*`), kèm lý do, mức cảnh báo và nội dung cảnh báo cho user.

Khi user trong danh sách **đăng nhập** (hoặc mở) portal:

1. **Ghi log** sự kiện `watchlist_hit`: thời điểm, IP, thiết bị, URL, pattern khớp, lý do.
2. **Cảnh báo admin** (`watchlist_login`, mức theo cấu hình) trên dashboard + Slack/Teams/Telegram. Mỗi lần đăng nhập đều cảnh báo; chỉ mở trang thì gộp lại, tối đa 1 cảnh báo mỗi 30 phút (`DLP_WATCHLIST_DEDUPE_MINUTES`).
3. **Hiện cảnh báo cho chính user**:
   - Hộp thoại đỏ phủ toàn trang portal. User phải bấm **"Tôi đã hiểu"** mới dùng tiếp được, và việc bấm được ghi log `warning_ack`.
   - Thông báo hệ thống của Windows/macOS.
   - Email cho user nếu đã cấu hình SMTP. Email gửi tới địa chỉ `notify_email` của mục trong danh sách, hoặc tới username nếu username là email.

So khớp được thực hiện trên cả định danh máy (employeeId / email Chrome) **và** tên gõ vào form đăng nhập portal. Vì vậy dùng tài khoản portal của người khác trên máy mình vẫn bị phát hiện. Với chế độ gateway, sự kiện vẫn được ghi log, admin vẫn được cảnh báo và email vẫn được gửi. Tuy nhiên không hiện được hộp thoại trên trình duyệt.

API: `GET /api/admin/watchlist`, `PUT|DELETE /api/admin/watchlist/{pattern}`, `POST /api/admin/watchlist/bulk` (`{"usernames": "a\nb, c", "reason": "...", "warn_message": "...", "severity": "high", "replace": false}`).

## Cảnh báo tự động

| Sự kiện | Mức |
|---|---|
| User trong danh sách theo dõi đăng nhập / truy cập portal | theo cấu hình (mặc định HIGH) |
| Download bị chặn | MEDIUM |
| ≥ 3 lần bị chặn trong 10 phút (cố tình tải) | HIGH |
| User bị khóa nhưng vẫn đăng nhập portal | HIGH |
| ≥ 5 lần đăng nhập thất bại trong 10 phút | HIGH |
| Download khi agent mất kết nối server | HIGH |
| Đăng nhập ngoài giờ làm việc (mặc định 7h–19h) | MEDIUM |
| User mới xuất hiện lần đầu | LOW |

Cảnh báo hiện trên dashboard và được đẩy tới Slack / MS Teams / Google Chat (`DLP_ALERT_WEBHOOK_URL`) hoặc Telegram.

## Cài đặt

### 1. Backend

```bash
cd dlp-monitor
cp .env.example .env     # điền DLP_AGENT_KEY, DLP_ADMIN_TOKEN (chuỗi ngẫu nhiên dài)
docker compose up -d --build
```

Mở `https://<server>:8080/`, nhập admin token. Production nên đặt sau HTTPS (Nginx/Traefik) và chỉ mở trong mạng nội bộ/VPN.

Chạy không dùng Docker:

```bash
cd backend
pip install -r requirements.txt
DLP_AGENT_KEY=... DLP_ADMIN_TOKEN=... uvicorn app.main:app --host 0.0.0.0 --port 8080
python -m pytest -q      # chạy test
```

### 2. Extension (chế độ A)

**Thử nghiệm:** `chrome://extensions` → bật Developer mode → *Load unpacked* → chọn thư mục `extension/` → mở *Options*, điền Server URL, Agent key, domain portal.

**Triển khai thật:**
1. Đóng gói extension, đưa lên Chrome Web Store ở chế độ *Private* (chỉ domain công ty) hoặc self-host file `.crx` + `update.xml`. Ghi lại `EXTENSION_ID`.
2. Đẩy policy bằng GPO: `deploy/policies/chrome-windows-gpo.reg`, `edge-windows-gpo.reg` (thay `EXTENSION_ID`, `UPDATE_URL`, domain, agent key). Với Intune / Google Admin Console dùng `chrome-managed-config.json`.
3. Policy kèm theo sẽ: ép cài + không cho gỡ extension, tắt Incognito/InPrivate, tắt DevTools, chặn extension lạ, bắt đăng nhập trình duyệt bằng tài khoản công ty.

**Định danh user** (theo thứ tự ưu tiên): `employeeId` do IT đẩy → email tài khoản Chrome/Edge công ty → username nhập vào form login portal. Khuyến nghị dùng 1 trong 2 cách đầu; cách thứ 3 chỉ là dự phòng vì user có thể gõ tên người khác.

### 3. Gateway (chế độ B, tùy chọn)

Xem `deploy/nginx-gateway.conf`. Nginx gọi `/api/gate` trước mỗi request; URL khớp `DLP_GATEWAY_DOWNLOAD_PATTERN` (mặc định: `/download`, `/export`, `/attachment`, các đuôi pdf/docx/xlsx/csv/zip…) sẽ được kiểm tra quyền. Danh tính lấy từ header SSO (`X-Portal-User`).

## Biến môi trường backend

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `DLP_AGENT_KEY` | – | Khóa cho extension/gateway |
| `DLP_ADMIN_TOKEN` | – | Token đăng nhập dashboard/admin API |
| `DLP_DB_PATH` | `dlp_monitor.db` | File SQLite |
| `DLP_DEFAULT_DOWNLOAD_ALLOWED` | `false` | Quyền của user chưa cấu hình |
| `DLP_AUTO_REGISTER_USERS` | `true` | Tự thêm user mới vào danh sách |
| `DLP_ALERT_WEBHOOK_URL` | – | Webhook Slack/Teams/Google Chat |
| `DLP_TELEGRAM_BOT_TOKEN`, `DLP_TELEGRAM_CHAT_ID` | – | Cảnh báo Telegram |
| `DLP_BURST_THRESHOLD` | `3` | Số lần bị chặn/10 phút để nâng HIGH |
| `DLP_WORK_HOUR_START` / `_END` | `7` / `19` | Khung giờ làm việc |
| `DLP_GATEWAY_DOWNLOAD_PATTERN` | xem code | Regex URL được coi là download |
| `DLP_DEFAULT_WARNING` | (câu mặc định) | Nội dung cảnh báo cho user trong watchlist |
| `DLP_WATCHLIST_DEDUPE_MINUTES` | `30` | Gộp cảnh báo admin khi user chỉ mở trang |
| `DLP_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_STARTTLS` | – / 587 / … | SMTP gửi email cảnh báo cho user |

## API chính

- `POST /api/agent/check-download` – extension hỏi cho/chặn (header `X-Agent-Key`)
- `POST /api/agent/event` – login, logout, login_failed, visit, agent_tamper
- `GET  /api/gate` – cho Nginx `auth_request` (204 cho qua / 403 chặn)
- `GET/PUT/DELETE /api/admin/users[/{username}]`, `GET /api/admin/events`, `GET /api/admin/alerts`, `POST /api/admin/alerts/{id}/ack`, `GET /api/admin/stats` (header `Authorization: Bearer <admin token>`)

## Giới hạn cần biết

Extension chặn được download qua trình duyệt, nhưng **không** chặn được: chụp màn hình, chụp bằng điện thoại, copy-paste nội dung hiển thị, dùng trình duyệt khác/máy cá nhân. Để kín hơn:
- Chặn trình duyệt khác bằng AppLocker/Intune; chỉ cho truy cập portal từ máy công ty (Conditional Access / IP whitelist nếu portal hỗ trợ).
- Kết hợp DLP endpoint (Microsoft Purview, v.v.) nếu cần kiểm soát clipboard / USB / in ấn.
- Chế độ gateway (B) là cách chặn mạnh nhất vì không phụ thuộc máy client.

## Lưu ý pháp lý

Giám sát nhân viên liên quan đến dữ liệu cá nhân (tại Việt Nam: Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân). Nên đưa nội dung giám sát vào nội quy/quy chế bảo mật, thông báo cho nhân viên, chỉ thu thập dữ liệu cần thiết và giới hạn người được xem log. Extension chỉ gửi dữ liệu khi truy cập các domain portal được cấu hình, chỉ ghi username (không bao giờ đọc/lưu mật khẩu), và popup của extension hiển thị rõ cho nhân viên biết hoạt động đang được ghi nhận.
