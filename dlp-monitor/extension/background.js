// Portal DLP Agent - service worker
// - Chặn download từ portal trước khi file được ghi xuống đĩa (downloads.onDeterminingFilename)
// - Gửi sự kiện login / logout / truy cập lên backend để giám sát & cảnh báo

const DEFAULTS = {
  serverUrl: "http://localhost:8080",
  agentKey: "change-me-agent-key",
  portalDomains: [],
  employeeId: "",
  failClosed: true,
  blockSaveAndPrint: true,
  usernameSelector: "",
};

// Cấu hình do IT đẩy (managed) luôn ưu tiên hơn cấu hình local (options page, chỉ dùng khi test).
// Cache trong bộ nhớ vì storage.managed.get có thể mất ~1s; làm mới khi storage thay đổi.
let configPromise = null;
async function loadConfig() {
  const local = await chrome.storage.local.get(Object.keys(DEFAULTS)).catch(() => ({}));
  let managed = {};
  try { managed = await chrome.storage.managed.get(null); } catch (e) { /* không có policy */ }
  const cfg = { ...DEFAULTS, ...local, ...managed };
  cfg.managed = Object.keys(managed).length > 0;
  cfg.portalDomains = (cfg.portalDomains || []).map((d) => d.trim().toLowerCase()).filter(Boolean);
  return cfg;
}
function getConfig() {
  if (!configPromise) configPromise = loadConfig();
  return configPromise;
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "managed" || Object.keys(changes).some((k) => k in DEFAULTS)) configPromise = null;
});
getConfig(); // khởi động sẵn

function hostOf(u) {
  try {
    if (u.startsWith("blob:")) u = u.slice(5); // blob:https://portal/uuid
    return new URL(u).hostname.toLowerCase();
  } catch (e) { return ""; }
}

function isPortalHost(host, cfg) {
  return !!host && cfg.portalDomains.some((d) => host === d || host.endsWith("." + d));
}

async function activeTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return tab?.url || "";
  } catch (e) { return ""; }
}

// Định danh user: employeeId do IT cấu hình > email Chrome profile công ty > username đăng nhập portal gần nhất
async function getIdentity(cfg) {
  if (cfg.employeeId) return cfg.employeeId;
  try {
    const info = await chrome.identity.getProfileUserInfo({ accountStatus: "ANY" });
    if (info?.email) return info.email;
  } catch (e) { /* ignore */ }
  const { lastPortalUser } = await chrome.storage.local.get("lastPortalUser");
  return lastPortalUser || "unknown";
}

async function api(cfg, path, body) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(cfg.serverUrl.replace(/\/$/, "") + path, {
      method: body ? "POST" : "GET",
      headers: { "Content-Type": "application/json", "X-Agent-Key": cfg.agentKey },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.json();
  } finally {
    clearTimeout(timer);
  }
}

// Hàng đợi sự kiện khi mất kết nối server -> gửi lại sau
async function queueEvent(evt) {
  const { pending = [] } = await chrome.storage.local.get("pending");
  pending.push(evt);
  await chrome.storage.local.set({ pending: pending.slice(-500) });
}

async function flushQueue() {
  const cfg = await getConfig();
  const { pending = [] } = await chrome.storage.local.get("pending");
  if (!pending.length) return;
  const left = [];
  for (const evt of pending) {
    try { await api(cfg, "/api/agent/event", evt); } catch (e) { left.push(evt); }
  }
  await chrome.storage.local.set({ pending: left });
}

async function sendEvent(type, url, detail = "", portalUsername = "") {
  const cfg = await getConfig();
  const evt = { username: await getIdentity(cfg), type, url, detail, portal_username: portalUsername,
    device: navigator.userAgent.slice(0, 200) };
  try { return await api(cfg, "/api/agent/event", evt); } catch (e) { await queueEvent(evt); return null; }
}

function notifyUser(title, message) {
  chrome.notifications.create({
    type: "basic", iconUrl: "icons/icon128.png", title, message, priority: 2,
  });
}

// ---------- Kiểm soát download ----------
chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  (async () => {
    const cfg = await getConfig();
    const candidates = [item.url, item.finalUrl, item.referrer].filter(Boolean);
    let fromPortal = candidates.some((u) => isPortalHost(hostOf(u), cfg));
    // data: URL (file sinh bằng JS) không mang domain -> dựa vào tab đang mở
    if (!fromPortal && /^(data:|blob:)/.test(item.url || "")) {
      fromPortal = isPortalHost(hostOf(await activeTabUrl()), cfg);
    }
    if (!fromPortal) { suggest(); return; }

    const username = await getIdentity(cfg);
    let allowed = false;
    let reason = "";
    try {
      const res = await api(cfg, "/api/agent/check-download", {
        username,
        url: (item.finalUrl || item.url || "").slice(0, 2000),
        filename: item.filename,
        size_bytes: Math.max(item.fileSize || item.totalBytes || 0, 0),
        mime: item.mime || "",
        device: navigator.userAgent.slice(0, 200),
      });
      allowed = !!res.allowed;
      reason = res.reason || "";
    } catch (e) {
      allowed = !cfg.failClosed;
      reason = "Không kết nối được máy chủ DLP" + (allowed ? " (cho phép tạm)" : " – chặn theo chính sách an toàn");
      await queueEvent({ username, type: "agent_tamper", url: item.url?.slice(0, 2000) || "",
        detail: "Download khi mất kết nối server: " + item.filename + " => " + (allowed ? "cho phép" : "chặn") });
    }

    if (allowed) {
      suggest();
    } else {
      try { await chrome.downloads.cancel(item.id); } catch (e) { /* ignore */ }
      suggest();
      try { await chrome.downloads.erase({ id: item.id }); } catch (e) { /* ignore */ }
      notifyUser("Download bị chặn", `${item.filename}\n${reason}\nLiên hệ quản trị viên nếu cần quyền.`);
    }
  })();
  return true; // suggest() gọi bất đồng bộ - Chrome giữ download chờ quyết định
});

// ---------- Nhận sự kiện từ content script ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const cfg = await getConfig();
    const pageUrl = sender.tab?.url || sender.url || "";
    const portal = isPortalHost(hostOf(pageUrl), cfg);
    if (msg.type === "getPortalContext") {
      if (!portal) return sendResponse({ portal: false });
      let policy = null;
      try { policy = await api(cfg, "/api/agent/policy?username=" + encodeURIComponent(await getIdentity(cfg))); } catch (e) {}
      return sendResponse({ portal: true, usernameSelector: cfg.usernameSelector,
        blockSaveAndPrint: cfg.blockSaveAndPrint && !(policy && policy.download_allowed) });
    }
    if (!portal) return sendResponse({ ok: false });
    let res = null;
    if (msg.type === "portalLogin" && msg.username) {
      const pu = String(msg.username).slice(0, 200);
      await chrome.storage.local.set({ lastPortalUser: pu });
      res = await sendEvent("login", pageUrl, "", pu);
    } else if (["login_failed", "logout", "visit", "warning_ack"].includes(msg.type)) {
      const { lastPortalUser = "" } = await chrome.storage.local.get("lastPortalUser");
      res = await sendEvent(msg.type, pageUrl, msg.detail || "", lastPortalUser);
    } else if (msg.type === "blockedShortcut") {
      res = await sendEvent("visit", pageUrl, "Bị chặn phím tắt " + msg.detail);
    }
    // User nằm trong danh sách theo dõi -> server trả warning: báo cho user bằng thông báo hệ thống
    const warning = res && res.warning;
    if (warning && msg.type === "portalLogin") notifyUser(warning.title || "Cảnh báo bảo mật", warning.message);
    sendResponse({ ok: true, warning });
  })();
  return true;
});

// Gửi lại sự kiện tồn đọng định kỳ
chrome.runtime.onStartup.addListener(flushQueue);
chrome.runtime.onInstalled.addListener(flushQueue);
chrome.alarms.create("flush", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "flush") flushQueue(); });
