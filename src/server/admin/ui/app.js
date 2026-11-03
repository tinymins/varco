"use strict";
// Hostnames, notes and names come from clients and other people, so all text goes
// in through textContent: el() has no way to set HTML. Paths are relative so the
// page works under a proxy prefix.

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "onclick" || key === "onsubmit" || key === "onchange" || key === "oninput") node[key] = value;
    else if (key === "class") node.className = value;
    else if (key === "value") node.value = value;
    else if (key === "hidden" || key === "disabled" || key === "required" || key === "selected") node[key] = true;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) node.append(child);
  }
  return node;
}

let toastTimer;
function toast(message) {
  const box = document.getElementById("toast");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { box.hidden = true; }, 4000);
}

async function api(method, path, body) {
  const options = { method, credentials: "same-origin" };
  if (method !== "GET") {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(body ?? {});
  }
  const response = await fetch("api/" + path, options);
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* not JSON, handled below */ }
  if (response.status === 401 && path !== "login") {
    boot();
    throw new Error("请先登录");
  }
  if (!response.ok) throw new Error(data?.error ?? "请求失败（" + response.status + "）");
  return data;
}

const time = (seconds) => seconds ? new Date(seconds * 1000).toLocaleString("zh-CN", { hour12: false }) : "—";
const short = (text) => text ? text.slice(0, 8) : "—";

function bytes(count) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = count ?? 0, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return (unit === 0 ? value : value.toFixed(1)) + " " + units[unit];
}

function field(label, input, cls) {
  return el("label", { class: cls }, label, input);
}

function run(action, done) {
  return async (event) => {
    event?.preventDefault?.();
    try {
      await action();
      if (done) toast(done);
      await refresh();
    } catch (error) {
      toast(error.message);
    }
  };
}

function ask(message, action, done) {
  return () => { if (confirm(message)) run(action, done)(); };
}

function table(headers, rows, empty) {
  if (!rows.length) return el("div", { class: "empty" }, empty);
  return el("div", { class: "scroll" }, el("table", {},
    el("tr", {}, headers.map((h) => el("th", {}, h))),
    rows));
}

// One-off secrets stay on screen until someone leaves the page or logs out.
function reveal(title, secret, extra) {
  return el("div", { class: "reveal" },
    el("strong", {}, title),
    el("code", { class: "mono" }, secret),
    extra ? el("div", { class: "mono" }, extra) : null,
    el("button", { type: "button", onclick: async (event) => {
      const code = event.target.parentElement.querySelector("code");
      try {
        await navigator.clipboard.writeText(code.textContent);
        toast("已复制");
      } catch {
        // The clipboard API needs HTTPS; selecting the text still lets it be copied.
        getSelection().selectAllChildren(code);
        toast("无法自动复制，已选中，请手动复制");
      }
    } }, "复制"));
}

// A list with search and paging, keeping its place between refreshes.
function pagedList(key, load, render) {
  const state = pages[key] ??= { q: "", offset: 0 };
  const box = el("div", {});
  const search = el("input", { type: "search", placeholder: "搜索", value: state.q, oninput: (event) => {
    state.q = event.target.value;
    state.offset = 0;
    clearTimeout(state.timer);
    state.timer = setTimeout(draw, 250);
  } });
  const body = el("div", {});
  const pager = el("div", { class: "pager muted" });
  box.append(el("div", { class: "toolbar" }, search), body, pager);
  async function draw() {
    const query = new URLSearchParams({ q: state.q, limit: PAGE, offset: state.offset });
    try {
      const page = await load(query.toString());
      body.replaceChildren(render(page.items));
      pager.replaceChildren(...(page.total > PAGE ? [
        el("button", { disabled: state.offset === 0, onclick: () => { state.offset = Math.max(0, state.offset - PAGE); draw(); } }, "上一页"),
        el("span", {}, (state.offset + 1) + "–" + Math.min(state.offset + PAGE, page.total) + " / " + page.total),
        el("button", { disabled: state.offset + PAGE >= page.total, onclick: () => { state.offset += PAGE; draw(); } }, "下一页"),
      ] : []));
    } catch (error) {
      toast(error.message);
    }
  }
  draw();
  return box;
}

const PAGE = 50;
const STATUS = { active: "可用", used: "已用完", expired: "已过期", revoked: "已撤销" };
const STANDING = { super: "超管", owner: "owner", admin: "管理员" };
const ROLE = { owner: "owner", admin: "管理员" };
const ACTIONS = {
  login: "登录", login_failed: "登录失败", logout: "退出", change_password: "修改密码", end_session: "结束会话",
  update_settings: "修改服务设置", create_workspace: "创建工作区", update_workspace: "修改工作区", delete_workspace: "删除工作区",
  delete_user: "删除账号", reset_password: "重置密码", add_admin: "添加管理员", remove_admin: "移除管理员", set_role: "修改角色",
  create_code: "生成 Code", update_code: "修改 Code", revoke_code: "撤销 Code", delete_code: "删除 Code",
  kick: "踢出", unkick: "解除踢出", add_ban: "拉黑", remove_ban: "解除拉黑", create_token: "创建 Token", delete_token: "删除 Token",
};

let me = null;
let pages = {};
let current = { scope: null, tab: null };
let revealed = {};
let poll = null;

const root = () => document.getElementById("root");
const wsPath = (path = "") => "w/" + current.scope + path;
const myWorkspace = () => me.workspaces.find((w) => w.id === current.scope);

// ---- Before the console opens ----

function showLogin() {
  stopPolling();
  me = null; pages = {}; revealed = {}; current = { scope: null, tab: null };
  const user = el("input", { autocomplete: "username", required: true });
  const pass = el("input", { type: "password", autocomplete: "current-password" });
  root().replaceChildren(el("div", { class: "narrow" }, el("section", {},
    el("h2", {}, "varco 管理后台"),
    el("form", { class: "stack", id: "login-form", onsubmit: async (event) => {
      event.preventDefault();
      try {
        await api("POST", "login", { username: user.value, password: pass.value });
        await boot();
      } catch (error) { toast(error.message); }
    } },
      field("用户名", user),
      field("密码", pass),
      el("button", { class: "primary" }, "登录")),
  )));
}

function showChangePassword() {
  stopPolling();
  const pass = el("input", { type: "password", id: "new-password", autocomplete: "new-password" });
  root().replaceChildren(el("div", { class: "narrow" }, el("section", {},
    el("h2", {}, "请先修改密码"),
    el("p", { class: "muted" }, "这是首次登录或密码刚被重置。密码没有任何限制，由你自己决定。"),
    el("form", { class: "stack", id: "password-form", onsubmit: async (event) => {
      event.preventDefault();
      try {
        await api("POST", "me/password", { password: pass.value });
        await boot();
      } catch (error) { toast(error.message); }
    } },
      field("新密码", pass),
      el("button", { class: "primary" }, "保存")),
    el("p", {}, el("button", { onclick: logout }, "退出")),
  )));
}

async function showSetup() {
  stopPolling();
  const settings = await api("GET", "settings");
  const addr = el("input", { id: "setup-addr", class: "mono", value: settings.public_addr ?? settings.suggested_public_addr, required: true });
  const listen = el("input", { id: "setup-listen", class: "mono", value: settings.relay_listen ?? settings.suggested_relay_listen, required: true });
  root().replaceChildren(el("div", { class: "narrow" }, el("section", {},
    el("h2", {}, "初始化服务"),
    el("p", { class: "muted" }, "客户端按对外地址连接中继。保存后中继开始监听。"),
    el("form", { class: "stack", id: "setup-form", onsubmit: async (event) => {
      event.preventDefault();
      try {
        await api("PUT", "settings", { public_addr: addr.value, relay_listen: listen.value });
        await boot();
      } catch (error) { toast(error.message); }
    } },
      field("对外地址（写进 Code）", addr),
      field("中继监听地址", listen),
      el("button", { class: "primary" }, "保存")),
  )));
}

async function logout() {
  try { await api("POST", "logout"); } catch (error) { toast(error.message); }
  showLogin();
}

async function boot() {
  try {
    me = await fetchMe();
  } catch {
    return showLogin();
  }
  if (!me) return showLogin();
  if (me.must_change_password) return showChangePassword();
  if (me.setup_needed) {
    try { return await showSetup(); } catch (error) { return toast(error.message); }
  }
  const keep = me.workspaces.some((w) => w.id === current.scope) || current.scope === "system";
  if (!keep) current = { scope: me.workspaces[0]?.id ?? (me.is_super ? "system" : null), tab: null };
  if (me.is_super && !me.workspaces.length) current = { scope: "system", tab: "workspaces" };
  drawApp();
  startPolling();
}

async function fetchMe() {
  const response = await fetch("api/me", { credentials: "same-origin" });
  if (response.status === 401) return null;
  if (!response.ok) throw new Error("请求失败（" + response.status + "）");
  return response.json();
}

// ---- The console ----

const WORKSPACE_TABS = [
  ["members", "在线成员"], ["codes", "Code"], ["bans", "黑名单"], ["connections", "连接历史"],
  ["audit", "审计"], ["tokens", "Token"], ["admins", "管理员"],
];
const SYSTEM_TABS = [
  ["workspaces", "工作区"], ["users", "账号"], ["sbans", "全局黑名单"], ["saudit", "全局审计"],
  ["stokens", "超管 Token"], ["settings", "服务设置"],
];

function tabsFor() {
  if (current.scope === "system") return SYSTEM_TABS;
  const standing = myWorkspace()?.standing;
  return WORKSPACE_TABS.filter(([key]) => key !== "admins" || standing !== "admin");
}

function drawApp() {
  const tabs = tabsFor();
  if (current.tab !== "me" && !tabs.some(([key]) => key === current.tab)) current.tab = tabs[0]?.[0] ?? null;
  const options = [
    ...(me.is_super ? [el("option", { value: "system", selected: current.scope === "system" }, "系统管理")] : []),
    ...me.workspaces.map((w) => el("option", { value: String(w.id), selected: w.id === current.scope }, w.name + "（" + STANDING[w.standing] + "）")),
  ];
  const content = el("main", { id: "content" });
  root().replaceChildren(
    el("header", {},
      el("h1", {}, "varco"),
      options.length ? el("select", { id: "scope", onchange: (event) => {
        const value = event.target.value;
        current = { scope: value === "system" ? "system" : Number(value), tab: null };
        pages = {};
        revealed = {};
        drawApp();
      } }, options) : null,
      el("span", { class: "spacer" }),
      el("span", { class: "muted" }, me.username),
      el("button", { onclick: () => { current.tab = "me"; drawApp(); } }, "我的账号"),
      el("button", { id: "logout", onclick: logout }, "退出")),
    tabs.length ? el("nav", {}, tabs.map(([key, label]) => el("button", {
      class: key === current.tab ? "active" : "", "data-tab": key,
      onclick: () => { current.tab = key; drawApp(); },
    }, label))) : null,
    content,
  );
  drawTab(content);
}

async function drawTab(content) {
  const draw = VIEWS[current.tab] ?? viewNothing;
  try {
    const view = await draw();
    content.replaceChildren(...[view].flat());
  } catch (error) {
    toast(error.message);
  }
}

// Forms keep what is being typed: only lists that nobody edits redraw on the timer.
async function refresh() {
  const content = document.getElementById("content");
  if (content) await drawTab(content);
}

function startPolling() {
  stopPolling();
  poll = setInterval(() => {
    if (current.tab === "members" && document.visibilityState === "visible") refresh().catch(() => {});
  }, 5000);
}

function stopPolling() {
  clearInterval(poll);
}

function viewNothing() {
  return el("section", {}, el("p", { class: "muted" }, "你的账号还没有加入任何工作区，请联系超管。"));
}

// ---- Workspace views ----

async function viewMembers() {
  const [overview, page, kicked] = await Promise.all([
    api("GET", wsPath()), api("GET", wsPath("/members?limit=500")), api("GET", wsPath("/kicked")),
  ]);
  const stats = overview.stats ?? {};
  const banIp = (m) => ask("拉黑 IP " + m.peer + "？同一出口后的所有人都会被断开，只在这个工作区生效。",
    () => api("POST", wsPath("/bans"), { kind: "ip", value: m.peer, note: m.hostname }), "已拉黑 IP");
  const banDevice = (m) => ask("拉黑设备 " + m.hostname + "？这台设备重开程序或换 Code 都进不来。克隆的系统可能共用同一个 ID。",
    () => api("POST", wsPath("/bans"), { kind: "device", value: m.device, note: m.hostname }), "已拉黑设备");
  return [
    el("div", { class: "chips" },
      el("div", { class: "chip" }, el("div", { class: "muted" }, overview.workspace.name + " · " + overview.workspace.cidr),
        el("strong", {}, (stats.online ?? 0) + " / " + (stats.capacity ?? 0)), "在线"),
      el("div", { class: "chip" }, el("div", { class: "muted" }, "累计收发（重启后清零）"),
        el("strong", {}, bytes(stats.rx_bytes) + " / " + bytes(stats.tx_bytes)))),
    el("section", {},
      el("h2", {}, "在线成员"),
      table(["主机名", "虚拟 IP", "来源 IP", "设备", "Code", "上线时间", "收 / 发", ""],
        page.items.map((m) => el("tr", {},
          el("td", {}, m.hostname),
          el("td", { class: "mono" }, m.ip),
          el("td", { class: "mono" }, m.peer ?? "—"),
          el("td", { class: "mono", title: m.device ?? "这台设备没有上报 ID，不能按设备拉黑" }, m.device ? short(m.device) : "未知设备"),
          el("td", { class: "mono" }, short(m.code)),
          el("td", {}, time(m.since)),
          el("td", {}, bytes(m.rx_bytes) + " / " + bytes(m.tx_bytes)),
          el("td", {},
            el("button", { class: "danger", onclick: ask("踢出 " + m.hostname + "？", () => api("POST", wsPath("/members/kick"), { id: m.id }), "已踢出") }, "踢出"),
            m.device ? el("button", { class: "danger", onclick: banDevice(m) }, "拉黑设备") : null,
            m.peer ? el("button", { class: "danger", onclick: banIp(m) }, "拉黑 IP") : null),
        )),
        "现在没有人在线"),
      el("p", { class: "muted" }, "踢出：断开并结束这次运行，对方重开程序后，只要 Code 还有效就能回来。要彻底拦住，请撤销 Code 并拉黑设备。")),
    kicked.length ? el("section", {},
      el("h2", {}, "已踢出"),
      table(["主机名", "时间", ""], kicked.map((k) => el("tr", {},
        el("td", {}, k.hostname),
        el("td", {}, time(k.at)),
        el("td", {}, el("button", { onclick: run(() => api("DELETE", wsPath("/kicked/" + encodeURIComponent(k.client))), "已解除") }, "解除")),
      )), ""),
      el("p", { class: "muted" }, "记录保留 7 天。解除后，那次运行如果还开着，会自动连回来。")) : null,
  ];
}

function limitText(code) {
  const parts = [];
  if (code.max_uses) parts.push("最多 " + code.max_uses + " 次");
  if (code.expires_at) parts.push("至 " + time(code.expires_at));
  return parts.join("，") || "永久";
}

function codeRows(items) {
  return table(["ID", "限制", "状态", "备注", "使用者", "创建时间", ""],
    items.map((c) => el("tr", {},
      el("td", { class: "mono", title: c.id }, short(c.id)),
      el("td", {}, limitText(c)),
      el("td", {}, el("span", { class: "badge " + c.status }, STATUS[c.status] ?? c.status)),
      el("td", { class: "wrap" }, c.note || "—"),
      el("td", { class: "wrap" }, c.used_by.length ? c.used_by.map((u) => u.hostname + "（" + u.peer + "）").join("，") : "—"),
      el("td", {}, time(c.created_at)),
      el("td", {},
        el("button", { onclick: () => {
          const note = prompt("备注", c.note);
          if (note !== null) run(() => api("PATCH", wsPath("/codes/" + c.id), { note }), "已保存")();
        } }, "改备注"),
        c.expires_at ? el("button", { onclick: () => {
          const duration = prompt("从现在起的有效时长，如 30m、24h、7d。不影响已连接的设备。", "24h");
          if (duration !== null) run(() => api("PATCH", wsPath("/codes/" + c.id), { duration }), "已保存")();
        } }, "改期限") : null,
        c.status !== "revoked" ? el("button", { class: "danger", onclick: ask("撤销这个 Code？用它进来的设备会被立即断开，且不能再连接。", () => api("POST", wsPath("/codes/" + c.id + "/revoke")), "已撤销") }, "撤销") : null,
        el("button", { class: "danger", onclick: ask("删除这条记录？如果 Code 还有效，也会一并撤销，用它进来的设备会被断开。", () => api("DELETE", wsPath("/codes/" + c.id)), "已删除") }, "删除")),
    )),
    "还没有生成过 Code");
}

const CODE_KINDS = {
  once: { label: "一次性", max: 1 },
  timed: { label: "限时（到期前不限次数）", duration: true },
  both: { label: "限时限次", max: true, duration: true },
  permanent: { label: "永久（适合无人值守的机器）" },
};

function viewCodes() {
  const kind = el("select", { id: "code-kind", onchange: () => sync() },
    Object.entries(CODE_KINDS).map(([key, value]) => el("option", { value: key }, value.label)));
  const duration = el("input", { id: "code-duration", value: "24h", placeholder: "30m、24h、7d" });
  const maxUses = el("input", { id: "code-max", type: "number", min: "1", value: "3" });
  const durationField = field("有效时长", duration);
  const maxField = field("最多使用次数（每次运行算一次）", maxUses);
  const note = el("input", { id: "code-note", placeholder: "发给谁、做什么用" });
  const ssh = el("input", { id: "code-ssh", class: "mono", placeholder: "ssh-ed25519 AAAA…" });
  const showCode = () => revealed.code ? reveal("Code 只显示这一次，请现在复制。", revealed.code.text, revealed.code.key) : "";
  const slot = el("div", {}, showCode());
  function sync() {
    const choice = CODE_KINDS[kind.value];
    durationField.hidden = !choice.duration;
    maxField.hidden = choice.max !== true;
  }
  sync();
  const form = el("form", { class: "grid", id: "code-form", onsubmit: async (event) => {
    event.preventDefault();
    const choice = CODE_KINDS[kind.value];
    const body = { note: note.value, ssh_pubkey: ssh.value };
    if (choice.duration) body.duration = duration.value;
    if (choice.max === true) body.max_uses = Number(maxUses.value);
    else if (choice.max) body.max_uses = choice.max;
    try {
      const created = await api("POST", wsPath("/codes"), body);
      revealed.code = {
        text: created.code,
        key: created.key_fingerprint ? "可远程控制的公钥：" + created.key_fingerprint : null,
      };
      slot.replaceChildren(showCode());
      note.value = ""; ssh.value = "";
      list.reload();
    } catch (error) { toast(error.message); }
  } },
    field("类型", kind), durationField, maxField, field("备注", note),
    field("SSH 公钥（可选，对方确认后持有私钥的人能远程控制对方电脑）", ssh, "wide"),
    el("div", {}, el("button", { class: "primary" }, "生成")));
  const list = reloadable("codes", (query) => api("GET", wsPath("/codes?" + query)), codeRows);
  return [
    el("section", {}, el("h2", {}, "生成 Code"), form, slot),
    el("section", {}, el("h2", {}, "已生成的 Code"), list.node),
  ];
}

// A paged list that a form next to it can ask to reload, without losing the form.
function reloadable(key, load, render) {
  const holder = el("div", {});
  const draw = () => holder.replaceChildren(pagedList(key, load, render));
  draw();
  return { node: holder, reload: draw };
}

function banRows(items, remove) {
  return table(["类型", "内容", "备注", "到期", "时间", ""],
    items.map((b) => el("tr", {},
      el("td", {}, b.kind === "ip" ? "IP" : "设备"),
      el("td", { class: "mono", title: b.value }, b.kind === "ip" ? b.value : short(b.value)),
      el("td", { class: "wrap" }, b.note || "—"),
      el("td", {}, b.expires_at ? time(b.expires_at) : "永久"),
      el("td", {}, time(b.created_at)),
      el("td", {}, el("button", { onclick: ask("解除这条拉黑？", () => remove(b.id), "已解除") }, "解除")),
    )),
    "黑名单是空的");
}

function banForm(submit, explanation) {
  const kind = el("select", { id: "ban-kind", onchange: () => {
    value.placeholder = kind.value === "ip" ? "203.0.113.7 或 198.51.100.0/24" : "64 位设备 ID";
  } }, el("option", { value: "ip" }, "IP 或网段"), el("option", { value: "device" }, "设备 ID"));
  const value = el("input", { id: "ban-value", class: "mono", required: true, placeholder: "203.0.113.7 或 198.51.100.0/24" });
  const note = el("input", { id: "ban-note" });
  const duration = el("input", { id: "ban-duration", placeholder: "留空为永久，或 30m、24h、7d" });
  return el("section", {},
    el("h2", {}, "添加黑名单"),
    el("form", { class: "grid", id: "ban-form", onsubmit: run(() => submit({ kind: kind.value, value: value.value, note: note.value, duration: duration.value }), "已拉黑") },
      field("类型", kind), field("内容", value), field("备注", note), field("时长", duration),
      el("div", {}, el("button", { class: "primary" }, "拉黑"))),
    el("p", { class: "muted" }, explanation));
}

function viewBans() {
  return [
    banForm((body) => api("POST", wsPath("/bans"), body),
      "立即断开匹配的连接，只在这个工作区生效。拉黑 IP 会影响同一出口后的所有人。设备 ID 由客户端上报，克隆的系统可能共用同一个 ID。"),
    el("section", {}, el("h2", {}, "黑名单"),
      pagedList("bans", (query) => api("GET", wsPath("/bans?" + query)),
        (items) => banRows(items, (id) => api("DELETE", wsPath("/bans/" + id))))),
  ];
}

function viewConnections() {
  return el("section", {}, el("h2", {}, "连接历史"),
    pagedList("connections", (query) => api("GET", wsPath("/connections?" + query)), (items) =>
      table(["主机名", "虚拟 IP", "来源 IP", "设备", "上线", "下线", "收 / 发"],
        items.map((c) => el("tr", {},
          el("td", {}, c.hostname),
          el("td", { class: "mono" }, c.ip),
          el("td", { class: "mono" }, c.peer),
          el("td", { class: "mono", title: c.device ?? "" }, c.device ? short(c.device) : "—"),
          el("td", {}, time(c.started_at)),
          el("td", {}, c.ended_at ? time(c.ended_at) : "在线"),
          el("td", {}, c.ended_at ? bytes(c.rx_bytes) + " / " + bytes(c.tx_bytes) : "—"),
        )),
        "还没有连接记录")));
}

function auditRows(items) {
  return table(["时间", "操作者", "动作", "对象", "来源"],
    items.map((a) => el("tr", {},
      el("td", {}, time(a.at)),
      el("td", {}, a.actor),
      el("td", {}, ACTIONS[a.action] ?? a.action),
      el("td", { class: "wrap mono" }, a.target || "—"),
      el("td", { class: "mono", title: "代理上报的来源，仅供参考" }, a.source || "—"),
    )),
    "还没有记录");
}

function viewAudit() {
  return el("section", {}, el("h2", {}, "审计"),
    pagedList("audit", (query) => api("GET", wsPath("/audit?" + query)), auditRows));
}

function tokensSection(items, create, remove, explanation) {
  const name = el("input", { id: "token-name", required: true, placeholder: "用途，如 ci" });
  const duration = el("input", { id: "token-duration", placeholder: "留空为永久，或 30m、24h、7d" });
  const slot = el("div", {});
  return [
    el("section", {}, el("h2", {}, "创建 Token"),
      el("form", { class: "grid", id: "token-form", onsubmit: async (event) => {
        event.preventDefault();
        try {
          const created = await create({ name: name.value, duration: duration.value });
          revealed.token = created.token;
          await refresh();
        } catch (error) { toast(error.message); }
      } }, field("名称", name), field("有效时长", duration), el("div", {}, el("button", { class: "primary" }, "创建"))),
      el("p", { class: "muted" }, explanation), slot,
      revealed.token ? reveal("Token 只显示这一次，请现在复制。", revealed.token) : null),
    el("section", {}, el("h2", {}, "Token"),
      table(["名称", "创建时间", "到期", "最后使用", ""],
        items.map((t) => el("tr", {},
          el("td", {}, t.name),
          el("td", {}, time(t.created_at)),
          el("td", {}, t.expires_at ? time(t.expires_at) : "永久"),
          el("td", {}, time(t.last_used)),
          el("td", {}, el("button", { class: "danger", onclick: ask("删除这个 Token？用它的脚本会立即失效。", () => remove(t.id), "已删除") }, "删除")),
        )),
        "还没有 Token")),
  ];
}

async function viewTokens() {
  const items = await api("GET", wsPath("/tokens"));
  return tokensSection(items, (body) => api("POST", wsPath("/tokens"), body), (id) => api("DELETE", wsPath("/tokens/" + id)),
    "脚本用 Authorization: Bearer 调用接口。权限等同这个工作区的普通管理员，不能增删管理员。");
}

async function viewAdmins() {
  const items = await api("GET", wsPath("/admins"));
  const username = el("input", { id: "admin-name", required: true });
  const password = el("input", { id: "admin-password", type: "password", autocomplete: "new-password" });
  const role = el("select", { id: "admin-role" }, el("option", { value: "admin" }, "管理员"), el("option", { value: "owner" }, "owner"));
  const canAttach = myWorkspace()?.standing === "super";
  const attach = el("input", { type: "checkbox", id: "admin-attach" });
  return [
    el("section", {}, el("h2", {}, "添加管理员"),
      el("form", { class: "grid", id: "admin-form", onsubmit: run(() => {
        const body = { username: username.value, role: role.value };
        if (!canAttach || !attach.checked) body.password = password.value;
        return api("POST", wsPath("/admins"), body);
      }, "已添加") },
        field("用户名", username), field("初始密码（首次登录时必须修改）", password), field("角色", role),
        canAttach ? field("使用已有账号（不用填密码）", attach) : null,
        el("div", {}, el("button", { class: "primary" }, "添加"))),
      el("p", { class: "muted" }, "只有 owner 能增删管理员。工作区至少保留一个 owner。")),
    el("section", {}, el("h2", {}, "管理员"),
      table(["用户名", "角色", ""],
        items.map((a) => el("tr", {},
          el("td", {}, a.username, a.shared ? el("span", { class: "muted" }, "（也属于其他工作区）") : null),
          el("td", {}, el("span", { class: "badge " + a.role }, ROLE[a.role])),
          el("td", {},
            el("button", { onclick: run(() => api("PATCH", wsPath("/admins/" + a.user_id), { role: a.role === "owner" ? "admin" : "owner" }), "已修改") }, a.role === "owner" ? "设为管理员" : "设为 owner"),
            el("button", { onclick: () => {
              const value = prompt("新的初始密码，对方下次登录时必须修改。对方当前的登录会被退出。");
              if (value !== null) run(() => api("POST", wsPath("/admins/" + a.user_id + "/password"), { password: value }), "已重置")();
            } }, "重置密码"),
            el("button", { class: "danger", onclick: ask("移除 " + a.username + "？", () => api("DELETE", wsPath("/admins/" + a.user_id)), "已移除") }, "移除")),
        )),
        "还没有管理员")),
  ];
}

// ---- System views ----

async function viewWorkspaces() {
  const list = await api("GET", "workspaces");
  const name = el("input", { id: "ws-name", required: true });
  const cidr = el("input", { id: "ws-cidr", class: "mono", required: true, value: list.suggested_cidr });
  const owner = el("input", { id: "ws-owner", placeholder: "可选" });
  const ownerPassword = el("input", { id: "ws-owner-password", type: "password", autocomplete: "new-password", placeholder: "首次登录时必须修改" });
  return [
    el("section", {}, el("h2", {}, "创建工作区"),
      el("form", { class: "grid", id: "workspace-form", onsubmit: async (event) => {
        event.preventDefault();
        const body = { name: name.value, cidr: cidr.value };
        if (owner.value.trim()) {
          body.owner_username = owner.value;
          if (ownerPassword.value) body.owner_password = ownerPassword.value;
        }
        try {
          await api("POST", "workspaces", body);
          toast("已创建");
          await boot();
        } catch (error) { toast(error.message); }
      } },
        field("名称", name), field("网段（/20 到 /30）", cidr), field("owner 用户名", owner), field("owner 初始密码", ownerPassword),
        el("div", {}, el("button", { class: "primary" }, "创建"))),
      el("p", { class: "muted" }, "每个工作区一张组网，相互隔离，网段可以重叠。owner 留空时可以稍后添加；填已有账号且不填密码，会把这个账号加进来。")),
    el("section", {}, el("h2", {}, "工作区"),
      table(["名称", "网段", "在线", "累计收 / 发", "创建时间", ""],
        list.items.map((w) => el("tr", {},
          el("td", {}, w.name),
          el("td", { class: "mono" }, w.cidr),
          el("td", {}, (w.stats?.online ?? 0) + " / " + (w.stats?.capacity ?? 0)),
          el("td", {}, bytes(w.stats?.rx_bytes) + " / " + bytes(w.stats?.tx_bytes)),
          el("td", {}, time(w.created_at)),
          el("td", {},
            el("button", { onclick: () => {
              const value = prompt("新名称", w.name);
              if (value !== null) updateWorkspace(w.id, { name: value }, "已改名");
            } }, "改名"),
            el("button", { onclick: () => {
              const value = prompt("新网段。所有成员会断开，重连后拿到新地址。", w.cidr);
              if (value !== null) updateWorkspace(w.id, { cidr: value }, "已修改网段");
            } }, "改网段"),
            el("button", { class: "danger", onclick: () => {
              if (prompt("删除工作区会断开所有成员，并删除它的 Code、记录和只属于它的账号，不能恢复。\n输入工作区名称确认：") === w.name) {
                deleteWorkspace(w.id);
              }
            } }, "删除")),
        )),
        "还没有工作区，先创建一个")),
  ];
}

async function updateWorkspace(id, body, done) {
  try {
    await api("PATCH", "workspaces/" + id, body);
    toast(done);
    await boot();
  } catch (error) { toast(error.message); }
}

async function deleteWorkspace(id) {
  try {
    await api("DELETE", "workspaces/" + id, {});
    toast("已删除");
    await boot();
  } catch (error) { toast(error.message); }
}

async function viewUsers() {
  const [users, workspaces] = await Promise.all([api("GET", "users"), api("GET", "workspaces")]);
  const nameOf = (id) => workspaces.items.find((w) => w.id === id)?.name ?? "?";
  return el("section", {}, el("h2", {}, "账号"),
    el("p", { class: "muted" }, "普通账号在工作区的“管理员”页添加。"),
    table(["用户名", "身份", "工作区", "待改密码", "创建时间", ""],
      users.map((u) => el("tr", {},
        el("td", {}, u.username),
        el("td", {}, u.is_super ? "超管" : "管理员"),
        el("td", { class: "wrap" }, u.workspaces.map(([id, role]) => nameOf(id) + "（" + ROLE[role] + "）").join("，") || "—"),
        el("td", {}, u.must_change_password ? "是" : "否"),
        el("td", {}, time(u.created_at)),
        el("td", {}, u.is_super ? null : [
          el("button", { onclick: () => {
            const value = prompt("新的初始密码，对方下次登录时必须修改。对方当前的登录会被退出。");
            if (value !== null) run(() => api("POST", "users/" + u.id + "/password", { password: value }), "已重置")();
          } }, "重置密码"),
          el("button", { class: "danger", onclick: ask("删除账号 " + u.username + "？", () => api("DELETE", "users/" + u.id), "已删除") }, "删除"),
        ]),
      )),
      "没有账号"));
}

function viewGlobalBans() {
  return [
    banForm((body) => api("POST", "bans", body),
      "对所有工作区生效。拉黑的 IP 在 TLS 之前就被丢弃。"),
    el("section", {}, el("h2", {}, "全局黑名单"),
      pagedList("sbans", (query) => api("GET", "bans?" + query),
        (items) => banRows(items, (id) => api("DELETE", "bans/" + id)))),
  ];
}

function viewGlobalAudit() {
  return el("section", {}, el("h2", {}, "全局审计"),
    pagedList("saudit", (query) => api("GET", "audit?" + query), auditRows));
}

async function viewGlobalTokens() {
  const items = await api("GET", "tokens");
  return tokensSection(items, (body) => api("POST", "tokens", body), (id) => api("DELETE", "tokens/" + id),
    "权限等同超管，可以访问 /metrics。请妥善保管。");
}

async function viewSettings() {
  const settings = await api("GET", "settings");
  const addr = el("input", { id: "set-addr", class: "mono", value: settings.public_addr ?? settings.suggested_public_addr });
  const listen = el("input", { id: "set-listen", class: "mono", value: settings.relay_listen ?? settings.suggested_relay_listen });
  const days = el("input", { id: "set-days", type: "number", min: "1", value: String(settings.history_days) });
  return el("section", {}, el("h2", {}, "服务设置"),
    el("p", { class: settings.relay_listening_on ? "muted" : "" }, settings.relay_listening_on ? "中继正在监听 " + settings.relay_listening_on : "中继没有在监听，请检查监听地址"),
    el("form", { class: "stack", id: "settings-form", onsubmit: run(() => api("PUT", "settings", {
      public_addr: addr.value, relay_listen: listen.value, history_days: Number(days.value),
    }), "已保存") },
      field("对外地址（写进新 Code，已发出的 Code 仍指向旧地址）", addr),
      field("中继监听地址（修改时已连接的成员不受影响）", listen),
      field("连接历史和审计保留天数", days),
      el("div", {}, el("button", { class: "primary" }, "保存"))));
}

async function viewMe() {
  const sessions = await api("GET", "me/sessions");
  const password = el("input", { id: "my-password", type: "password", autocomplete: "new-password" });
  return [
    el("section", {}, el("h2", {}, "修改密码"),
      el("form", { class: "stack", id: "my-password-form", onsubmit: run(() => api("POST", "me/password", { password: password.value }), "已修改，其他登录已退出") },
        field("新密码", password), el("div", {}, el("button", { class: "primary" }, "保存")))),
    el("section", {}, el("h2", {}, "登录中的会话"),
      table(["设备", "登录时间", "最近活动", ""],
        sessions.map((s) => el("tr", {},
          el("td", { class: "wrap" }, s.user_agent || "—"),
          el("td", {}, time(s.created_at)),
          el("td", {}, time(s.last_seen)),
          el("td", {}, el("button", { class: "danger", onclick: run(() => api("DELETE", "me/sessions/" + s.id), "已结束") }, "结束")),
        )),
        "")),
  ];
}

const VIEWS = {
  members: viewMembers, codes: viewCodes, bans: viewBans, connections: viewConnections,
  audit: viewAudit, tokens: viewTokens, admins: viewAdmins,
  workspaces: viewWorkspaces, users: viewUsers, sbans: viewGlobalBans, saudit: viewGlobalAudit,
  stokens: viewGlobalTokens, settings: viewSettings, me: viewMe,
};

boot();
