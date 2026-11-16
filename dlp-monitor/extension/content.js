// Chạy trên mọi trang nhưng chỉ gửi dữ liệu khi background xác nhận đây là portal được giám sát.
// Listener được gắn ngay (đồng bộ) để không bỏ lỡ lần đăng nhập nếu user submit rất nhanh.
(() => {
  const KEY = "__dlp_pending_login";
  const ctxPromise = chrome.runtime.sendMessage({ type: "getPortalContext" }).catch(() => null);
  const send = (m) => chrome.runtime.sendMessage(m).catch(() => {});
  const hasPasswordField = () => !!document.querySelector('input[type="password"]');
  let ctx = null; // null = chưa biết; {portal:false} = không phải portal

  // ---- Cảnh báo cho user nằm trong danh sách theo dõi ----
  // Hộp thoại phủ toàn trang, user phải bấm "Tôi đã hiểu" (ghi log xác nhận). Mỗi tab chỉ hiện 1 lần / phiên.
  function showWarning(w, force) {
    if (!w || document.getElementById("__dlp_warn")) return;
    if (!force && sessionStorage.getItem("__dlp_warned")) return;
    const host = document.createElement("div");
    host.id = "__dlp_warn";
    host.style.cssText = "position:fixed;inset:0;z-index:2147483647";
    const root = host.attachShadow({ mode: "closed" }); // tách khỏi CSS của portal
    root.innerHTML = `
      <style>
        .bg{position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;padding:16px;font:15px/1.5 system-ui,sans-serif}
        .box{background:#fff;color:#1d2330;max-width:460px;width:100%;border-radius:10px;padding:22px;border-top:6px solid #dc2626;box-shadow:0 10px 40px rgba(0,0,0,.35)}
        h2{margin:0 0 10px;font-size:19px;color:#b91c1c}
        p{margin:0 0 18px;white-space:pre-wrap}
        button{background:#dc2626;color:#fff;border:0;border-radius:6px;padding:9px 18px;font-size:15px;cursor:pointer}
        @media (prefers-color-scheme:dark){.box{background:#1f2430;color:#e6e8ee}h2{color:#f87171}}
      </style>
      <div class="bg" role="alertdialog" aria-modal="true" aria-labelledby="t">
        <div class="box"><h2 id="t"></h2><p id="m"></p><button id="ok">Tôi đã hiểu</button></div>
      </div>`;
    root.getElementById("t").textContent = "⚠️ " + (w.title || "Cảnh báo bảo mật");
    root.getElementById("m").textContent = w.message || "";
    root.getElementById("ok").addEventListener("click", () => {
      sessionStorage.setItem("__dlp_warned", "1");
      host.remove();
      send({ type: "warning_ack", detail: "Xác nhận cảnh báo (event " + (w.event_id || "?") + ")" });
    });
    (document.body || document.documentElement).appendChild(host);
    root.getElementById("ok").focus();
  }
  // Đăng nhập luôn hiện cảnh báo; truy cập trang chỉ hiện 1 lần / phiên tab
  const sendAndWarn = (m) => chrome.runtime.sendMessage(m)
    .then((r) => r && r.warning && showWarning(r.warning, m.type === "portalLogin")).catch(() => {});

  // ---- Bắt đăng nhập ----
  function findUsername(form) {
    const sel = ctx && ctx.usernameSelector;
    const el = (sel && document.querySelector(sel)) ||
      form.querySelector('input[type="email"]') ||
      form.querySelector('input[name*="user" i], input[id*="user" i], input[name*="login" i], input[name*="email" i], input[autocomplete="username"]') ||
      form.querySelector('input[type="text"]');
    return el && el.value ? el.value.trim() : "";
  }
  function onLoginAttempt(form) {
    if (ctx && !ctx.portal) return;
    if (!form || !form.querySelector('input[type="password"]')) return;
    const u = findUsername(form);
    if (u) sessionStorage.setItem(KEY, u.slice(0, 200)); // chỉ lưu username, không bao giờ lưu mật khẩu
  }
  document.addEventListener("submit", (e) => onLoginAttempt(e.target), true);
  // Nhiều SPA đăng nhập bằng nút bấm / Enter mà không submit form
  document.addEventListener("click", (e) => {
    const b = e.target.closest && e.target.closest('button, input[type="submit"]');
    if (b) onLoginAttempt(b.form || b.closest("form") || document);
  }, true);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target && e.target.type === "password") onLoginAttempt(e.target.form || document);
  }, true);

  // ---- Logout ----
  document.addEventListener("click", (e) => {
    if (!ctx || !ctx.portal) return;
    const a = e.target.closest && e.target.closest("a, button");
    if (a && /log\s?out|sign\s?out|đăng xuất/i.test((a.textContent || "") + (a.getAttribute("href") || ""))) {
      send({ type: "logout" });
    }
  }, true);

  // ---- Chặn Ctrl+S / Ctrl+P (lưu trang / in PDF) khi user không có quyền download ----
  window.addEventListener("keydown", (e) => {
    if (!ctx || !ctx.blockSaveAndPrint) return;
    const k = (e.key || "").toLowerCase();
    if ((e.ctrlKey || e.metaKey) && (k === "s" || k === "p")) {
      e.preventDefault(); e.stopImmediatePropagation();
      send({ type: "blockedShortcut", detail: "Ctrl+" + k.toUpperCase() });
      alert("Chức năng này bị chặn theo chính sách bảo mật của công ty.");
    }
  }, true);

  ctxPromise.then((c) => {
    ctx = c || { portal: false };
    if (!ctx.portal) { sessionStorage.removeItem(KEY); return; }

    // Ghi nhận truy cập portal (1 lần / phiên tab)
    if (!sessionStorage.getItem("__dlp_visit")) {
      sessionStorage.setItem("__dlp_visit", "1");
      sendAndWarn({ type: "visit" });
    }

    // Kết quả lần submit login trước đó (sau khi trang chuyển)
    const pending = sessionStorage.getItem(KEY);
    if (pending) {
      setTimeout(() => {
        if (sessionStorage.getItem(KEY) !== pending) return;
        sessionStorage.removeItem(KEY);
        // Sau submit vẫn còn form mật khẩu => đăng nhập thất bại
        if (hasPasswordField()) send({ type: "login_failed", detail: "portal_username=" + pending });
        else sendAndWarn({ type: "portalLogin", username: pending });
      }, 1500);
    }

    // SPA: đăng nhập thành công mà không reload -> form mật khẩu biến mất
    let hadPwd = hasPasswordField();
    new MutationObserver(() => {
      const now = hasPasswordField();
      if (hadPwd && !now) {
        const u = sessionStorage.getItem(KEY);
        if (u) { sessionStorage.removeItem(KEY); sendAndWarn({ type: "portalLogin", username: u }); }
      }
      hadPwd = now;
    }).observe(document.documentElement, { childList: true, subtree: true });
  });
})();
