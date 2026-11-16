(async () => {
  const $ = (id) => document.getElementById(id);
  const local = await chrome.storage.local.get(null);
  let managed = {};
  try { managed = await chrome.storage.managed.get(null); } catch (e) {}
  const cfg = { serverUrl: "http://localhost:8080", agentKey: "change-me-agent-key", ...local, ...managed };
  let user = managed.employeeId || local.employeeId || "";
  if (!user) {
    try { user = (await chrome.identity.getProfileUserInfo({ accountStatus: "ANY" })).email; } catch (e) {}
  }
  user = user || local.lastPortalUser || "unknown";
  $("user").textContent = user;
  $("mode").textContent = Object.keys(managed).length ? "Cấu hình do IT quản lý" : "Cấu hình local (chế độ thử nghiệm)";
  try {
    const r = await fetch(cfg.serverUrl.replace(/\/$/, "") + "/api/agent/policy?username=" + encodeURIComponent(user),
      { headers: { "X-Agent-Key": cfg.agentKey } });
    if (!r.ok) throw new Error(r.status);
    const p = await r.json();
    $("srv").innerHTML = '<span class="ok">Đã kết nối</span>';
    $("dl").innerHTML = p.download_allowed ? '<span class="ok">Được phép</span>' : '<span class="bad">Bị chặn</span>';
  } catch (e) {
    $("srv").innerHTML = '<span class="bad">Mất kết nối</span>';
    $("dl").textContent = "Không xác định";
  }
})();
