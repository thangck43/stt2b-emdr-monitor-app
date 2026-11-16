const ids = ["serverUrl", "agentKey", "portalDomains", "employeeId", "usernameSelector", "failClosed", "blockSaveAndPrint"];
(async () => {
  const c = await chrome.storage.local.get(ids);
  for (const id of ids) {
    const el = document.getElementById(id);
    if (c[id] === undefined) continue;
    if (el.type === "checkbox") el.checked = !!c[id];
    else el.value = Array.isArray(c[id]) ? c[id].join(",") : c[id];
  }
  try {
    const m = await chrome.storage.managed.get(null);
    if (Object.keys(m).length) document.getElementById("managedNote").textContent =
      "⚠️ Đang có cấu hình do IT quản lý – các trường tương ứng ở đây sẽ bị bỏ qua.";
  } catch (e) {}
})();
document.getElementById("save").onclick = async () => {
  const v = {};
  for (const id of ids) {
    const el = document.getElementById(id);
    v[id] = el.type === "checkbox" ? el.checked : el.value.trim();
  }
  v.portalDomains = v.portalDomains.split(",").map((s) => s.trim()).filter(Boolean);
  await chrome.storage.local.set(v);
  document.getElementById("msg").textContent = "Đã lưu";
};
