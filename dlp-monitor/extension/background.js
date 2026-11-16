// Portal DLP Agent - service worker
// - Chặn download từ portal trước khi file được ghi xuống đĩa (downloads.onDeterminingFilename)
// - Gửi sự kiện login / logout / truy cập lên backend để giám sát & cảnh báo

const DEFAULTS = {
  serverUrl: "http://localhost:8080",
  agentKey: "change-me-agent-key",
  portalDomains: [],
  // Portal bên thứ ba thường chuyển sang trang SSO ở domain khác để đăng nhập
  // (vd login.microsoftonline.com, *.okta.com). Chỉ giám sát các domain này khi tab đi từ portal sang.
  loginDomains: [],
  // Domain chứa file của portal (CDN / storage), vd "xxx.blob.core.windows.net"
  fileDomains: [],
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
  const norm = (l) => (Array.isArray(l) ? l : String(l || "").split(","))
    .map((d) => String(d).trim().toLowerCase().replace(/^\*\./, "")).filter(Boolean);
  cfg.portalDomains = norm(cfg.portalDomains);
  cfg.loginDomains = norm(cfg.loginDomains);
  cfg.fileDomains = norm(cfg.fileDomains);
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

function hostIn(host, list) {
  return !!host && list.some((d) => host === d || host.endsWith("." + d));
}
function isPortalHost(host, cfg) {
  return hostIn(host, cfg.portalDomains);
}

// ---- Theo dõi tab đang ở luồng portal (để nhận ra trang SSO bên thứ ba thuộc về portal) ----
const FLOW_TTL_MS = 15 * 60 * 1000;
async function sessGet(key) {
  try { return (await chrome.storage.session.get(key))[key] || {}; } catch (e) { return {}; }
}
async function sessSet(key, val) {
  try { await chrome.storage.session.set({ [key]: val }); } catch (e) { /* ignore */ }
}
async function markPortalTab(tabId) {
  const t = await sessGet("portalTabs"); t[tabId] = Date.now(); await sessSet("portalTabs", t);
}
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  const url = info.url || (info.status === "loading" ? tab.url : "");
  if (!url) return;
  const cfg = await getConfig();
  if (isPortalHost(hostOf(url), cfg)) markPortalTab(tabId);
});
chrome.tabs.onRemoved.addListener(async (tabId) => {
  for (const k of ["portalTabs", "pendingLogins"]) {
    const t = await sessGet(k); delete t[tabId]; await sessSet(k, t);
  }
});

// Vai trò của trang: "portal" | "login" (trang SSO trong luồng đăng nhập portal) | ""
async function pageRole(url, tabId, cfg) {
  const host = hostOf(url);
  if (isPortalHost(host, cfg)) return "portal";
  if (!hostIn(host, cfg.loginDomains)) return "";
  let decoded = url;
  try { decoded = decodeURIComponent(url); } catch (e) { /* ignore */ }
  // redirect_uri / returnUrl trỏ về portal
  if (cfg.portalDomains.some((d) => decoded.toLowerCase().includes(d))) { if (tabId != null) markPortalTab(tabId); return "login"; }
  const t = await sessGet("portalTabs");
  return tabId != null && t[tabId] && Date.now() - t[tabId] < FLOW_TTL_MS ? "login" : "";
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
    let fromPortal = candidates.some((u) => {
      const h = hostOf(u);
      return isPortalHost(h, cfg) || hostIn(h, cfg.fileDomains);
    });
    // data:/blob: (file sinh bằng JS) hoặc link không có referrer -> dựa vào tab đang mở
    if (!fromPortal && (!item.referrer || /^(data:|blob:)/.test(item.url || ""))) {
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
    const tabId = sender.tab?.id;
    const role = await pageRole(pageUrl, tabId, cfg);
    const portal = role !== "";
    if (msg.type === "getPortalContext") {
      if (!portal) return sendResponse({ portal: false });
      if (role === "login") return sendResponse({ portal: true, loginOnly: true, usernameSelector: cfg.usernameSelector });
      let policy = null;
      try { policy = await api(cfg, "/api/agent/policy?username=" + encodeURIComponent(await getIdentity(cfg))); } catch (e) {}
      return sendResponse({ portal: true, usernameSelector: cfg.usernameSelector,
        blockSaveAndPrint: cfg.blockSaveAndPrint && !(policy && policy.download_allowed) });
    }
    if (!portal) return sendResponse({ ok: false });
    // Lần đăng nhập đang chờ: lưu theo tab vì sessionStorage không theo được khi chuyển domain SSO -> portal
    if (msg.type === "loginAttempt") {
      const p = await sessGet("pendingLogins");
      if (tabId != null) {
        const prev = p[tabId] && Date.now() - p[tabId].ts < FLOW_TTL_MS ? p[tabId] : null;
        // Bước mật khẩu không thấy username (SSO 2 bước) -> dùng username đã nhập ở bước trước
        const username = String(msg.username || (prev && prev.username) || "").slice(0, 200);
        if (username) p[tabId] = { username, stage: msg.stage === "user" ? "user" : "password", ts: Date.now() };
      }
      await sessSet("pendingLogins", p);
      return sendResponse({ ok: true });
    }
    if (msg.type === "peekPendingLogin") {
      const p = await sessGet("pendingLogins");
      const e = tabId != null ? p[tabId] : null;
      return sendResponse({ role, pending: e && Date.now() - e.ts < FLOW_TTL_MS ? e : null });
    }
    if (["portalLogin", "login_failed"].includes(msg.type) && tabId != null) {
      const p = await sessGet("pendingLogins");
      // Sai mật khẩu: giữ username cho lần thử lại (trang báo lỗi thường không hiện lại ô username)
      if (msg.type === "login_failed" && p[tabId]) p[tabId] = { ...p[tabId], stage: "user", ts: Date.now() };
      else delete p[tabId];
      await sessSet("pendingLogins", p);
    }
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
