"use strict";
// State, API calls and views. Everything on screen is built from components.js.
// Paths are relative so the page works under a proxy prefix.

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

// Make a change, say so, redraw. Buttons and forms show a failure in a toast.
function changes(action, done) {
  return async () => {
    await action();
    if (done) toast(done, "success");
    await refresh();
  };
}

function ask(message, action, done, { danger = true, confirmLabel } = {}) {
  return () => dialog({
    message, danger, confirmLabel, action,
    after: () => { toast(done, "success"); return refresh(); },
  });
}

function askText({ label, value, type, placeholder, ready, ...rest }, action, done, after = refresh) {
  return () => dialog({
    ...rest, ready, action,
    control: field(label, input({ type, value, placeholder, autocomplete: type === "password" ? "new-password" : "off" })),
    after: () => { toast(done, "success"); return after(); },
  });
}

const askNewPassword = (path) => askText({
  title: "重置密码",
  message: "新的初始密码，对方下次登录时必须修改。对方当前的登录会被退出。",
  label: "新的初始密码",
  type: "password",
}, (password) => api("POST", path, { password }), "已重置");

const STATUS = { active: "可用", used: "已用完", expired: "已过期", revoked: "已撤销" };
const STATUS_TONE = { active: "success", used: "muted", expired: "muted", revoked: "muted" };
const STANDING = { super: "超管", owner: "owner", admin: "管理员" };
const ROLE = { owner: "owner", admin: "管理员" };
const ROLE_TONE = { owner: "success", admin: "neutral" };
const ACTIONS = {
  login: "登录", login_failed: "登录失败", logout: "退出", change_password: "修改密码", end_session: "结束会话",
  update_settings: "修改服务设置", create_workspace: "创建工作区", update_workspace: "修改工作区", delete_workspace: "删除工作区",
  delete_user: "删除账号", reset_password: "重置密码", add_admin: "添加管理员", remove_admin: "移除管理员", set_role: "修改角色",
  create_code: "生成 Code", update_code: "修改 Code", revoke_code: "撤销 Code", delete_code: "删除 Code",
  copy_code: "复制 Code", copy_token: "复制 Token", add_ssh_key: "添加 SSH 公钥", delete_ssh_key: "删除 SSH 公钥",
  kick: "踢出", unkick: "解除踢出", add_ban: "拉黑", remove_ban: "解除拉黑", create_token: "创建 Token", delete_token: "删除 Token",
};

let me = null;
let pages = {};
let current = { scope: null, tab: null };
let poll = null;

const wsPath = (path = "") => "w/" + current.scope + path;
const myWorkspace = () => me.workspaces.find((w) => w.id === current.scope);
const list = (key, load, render) => pagedList(pages[key] ??= { q: "", offset: 0 }, load, render);

function show(...nodes) {
  closeOverlays();
  document.getElementById("root").replaceChildren(...nodes);
}

// ---- Before the console opens ----

function showLogin() {
  stopPolling();
  me = null; pages = {}; current = { scope: null, tab: null };
  const user = input({ autocomplete: "username", required: true });
  const pass = input({ type: "password", autocomplete: "current-password" });
  show(authPage("varco 管理后台", null,
    formOf({ id: "login-form", layout: "stack" }, async () => {
      await api("POST", "login", { username: user.value, password: pass.value });
      await boot();
    },
      field("用户名", user),
      field("密码", pass),
      formActions(submitButton("登录")))));
}

function showChangePassword() {
  stopPolling();
  const pass = input({ type: "password", id: "new-password", autocomplete: "new-password" });
  show(authPage("请先修改密码", "这是首次登录或密码刚被重置。密码没有任何限制，由你自己决定。",
    formOf({ id: "password-form", layout: "stack" }, async () => {
      await api("POST", "me/password", { password: pass.value });
      await boot();
    },
      field("新密码", pass),
      formActions(submitButton("保存"))),
    button("退出", { variant: "ghost", onclick: logout })));
}

async function showSetup() {
  stopPolling();
  const settings = await api("GET", "settings");
  const addr = input({ id: "setup-addr", mono: true, value: settings.public_addr ?? settings.suggested_public_addr, required: true });
  const listen = input({ id: "setup-listen", mono: true, value: settings.relay_listen ?? settings.suggested_relay_listen, required: true });
  show(authPage("初始化服务", "客户端按对外地址连接中继。保存后中继开始监听。",
    formOf({ id: "setup-form", layout: "stack" }, async () => {
      await api("PUT", "settings", { public_addr: addr.value, relay_listen: listen.value });
      await boot();
    },
      field("对外地址（写进 Code）", addr),
      field("中继监听地址", listen),
      formActions(submitButton("保存")))));
}

async function logout() {
  try { await api("POST", "logout"); } catch (error) { toast(error.message, "error"); }
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
    try { return await showSetup(); } catch (error) { return toast(error.message, "error"); }
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

function switchScope(scope) {
  current = { scope, tab: null };
  pages = {};
  drawApp();
}

function userMenu() {
  const scopes = [
    ...(me.is_super ? [{ label: "系统管理", icon: "shield", checked: current.scope === "system", onselect: () => switchScope("system") }] : []),
    ...me.workspaces.map((w) => ({
      label: w.name, hint: STANDING[w.standing], icon: "layers", checked: w.id === current.scope, onselect: () => switchScope(w.id),
    })),
  ];
  const trigger = el("button", { type: "button", id: "user-menu", class: "user-trigger" },
    el("span", { class: "user-avatar" }, me.username.slice(0, 1).toUpperCase()),
    el("span", { class: "user-name" }, me.username),
    icon("chevron"));
  return dropdownMenu(trigger, [
    scopes.length ? { title: "切换工作区", scroll: true, items: scopes } : null,
    { items: [
      { label: "我的账号设置", icon: "settings", checked: current.tab === "me", onselect: () => { current.tab = "me"; drawApp(); } },
      { label: "退出", id: "logout", icon: "logout", onselect: logout },
    ] },
  ]);
}

function drawApp() {
  const items = tabsFor();
  if (current.tab !== "me" && !items.some(([key]) => key === current.tab)) current.tab = items[0]?.[0] ?? null;
  const scopeName = current.scope === "system" ? "系统管理" : myWorkspace()?.name;
  const content = el("main", { id: "content" });
  show(
    el("header", { class: "topbar" },
      logo(),
      scopeName && el("span", { class: "topbar-scope", title: scopeName }, scopeName),
      el("span", { class: "topbar-spacer" }),
      userMenu()),
    items.length ? tabs(items, current.tab, (key) => { current.tab = key; drawApp(); }) : null,
    content,
  );
  drawTab(content);
}

async function drawTab(content) {
  const draw = VIEWS[current.tab] ?? viewNothing;
  try {
    const view = await draw();
    content.replaceChildren(...[view].flat().filter(Boolean));
  } catch (error) {
    toast(error.message, "error");
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
  return card(null, {}, el("p", { class: "muted" }, "你的账号还没有加入任何工作区，请联系超管。"));
}

// ---- Workspace views ----

async function viewMembers() {
  const [overview, page, kicked] = await Promise.all([
    api("GET", wsPath()), api("GET", wsPath("/members?limit=500")), api("GET", wsPath("/kicked")),
  ]);
  const summary = overview.stats ?? {};
  const banIp = (m) => ask("拉黑 IP " + m.peer + "？同一出口后的所有人都会被断开，只在这个工作区生效。",
    () => api("POST", wsPath("/bans"), { kind: "ip", value: m.peer, note: m.hostname }), "已拉黑 IP", { confirmLabel: "拉黑" });
  const banDevice = (m) => ask("拉黑设备 " + m.hostname + "？这台设备重开程序或换 Code 都进不来。克隆的系统可能共用同一个 ID。",
    () => api("POST", wsPath("/bans"), { kind: "device", value: m.device, note: m.hostname }), "已拉黑设备", { confirmLabel: "拉黑" });
  return [
    stats(
      stat(overview.workspace.name + " · " + overview.workspace.cidr, (summary.online ?? 0) + " / " + (summary.capacity ?? 0), "在线"),
      stat("累计收发（重启后清零）", bytes(summary.rx_bytes) + " / " + bytes(summary.tx_bytes))),
    card("在线成员", { hint: "踢出：断开并结束这次运行，对方重开程序后，只要 Code 还有效就能回来。要彻底拦住，请撤销 Code 并拉黑设备。" },
      dataTable(["主机名", "虚拟 IP", "来源 IP", "设备", "Code", "上线时间", "收 / 发", "操作"],
        page.items.map((m) => [
          m.hostname,
          monoCell(m.ip),
          monoCell(m.peer ?? "—"),
          monoCell(m.device ? short(m.device) : "未知设备", m.device ?? "这台设备没有上报 ID，不能按设备拉黑"),
          monoCell(short(m.code)),
          time(m.since),
          bytes(m.rx_bytes) + " / " + bytes(m.tx_bytes),
          rowActions(
            rowButton("踢出", ask("踢出 " + m.hostname + "？", () => api("POST", wsPath("/members/kick"), { id: m.id }), "已踢出", { confirmLabel: "踢出" }), { danger: true }),
            m.device && rowButton("拉黑设备", banDevice(m), { danger: true }),
            m.peer && rowButton("拉黑 IP", banIp(m), { danger: true })),
        ]),
        "现在没有人在线")),
    kicked.length ? card("已踢出", { hint: "记录保留 7 天。解除后，那次运行如果还开着，会自动连回来。" },
      dataTable(["主机名", "时间", "操作"], kicked.map((k) => [
        k.hostname,
        time(k.at),
        rowActions(rowButton("解除", changes(() => api("DELETE", wsPath("/kicked/" + encodeURIComponent(k.client))), "已解除"))),
      ]), "")) : null,
  ];
}

function limitText(code) {
  const parts = [];
  if (code.max_uses) parts.push("最多 " + code.max_uses + " 次");
  if (code.expires_at) parts.push("至 " + time(code.expires_at));
  return parts.join("，") || "永久";
}

async function showCodeCopies(id) {
  const copies = await api("GET", wsPath("/codes/" + id + "/copies"));
  sheet({ title: "复制 Code" },
    secretRow({ label: "默认 Code", hint: "只入网", secret: copies.code }),
    copies.keyed.length
      ? notice("联合 Code 让对方粘贴后入网并开启 SSH，持有对应私钥的人能远程控制对方电脑，只发给知情并同意的人。", "warn")
      : el("p", { class: "muted" }, "在“我的账号设置”里添加 SSH 公钥后，这里会多出对应的联合 Code。"),
    copies.keyed.map((key) => secretRow({ label: "联合 Code：" + key.name, hint: key.fingerprint, secret: key.code })));
}

function codeRows(items) {
  return dataTable(["ID", "限制", "状态", "备注", "使用者", "创建时间", "操作"],
    items.map((c) => [
      monoCell(short(c.id), c.id),
      limitText(c),
      badge(STATUS[c.status] ?? c.status, STATUS_TONE[c.status]),
      cell(c.note || "—", { wrap: true }),
      cell(c.used_by.length ? c.used_by.map((u) => u.hostname + "（" + u.peer + "）").join("，") : "—", { wrap: true }),
      time(c.created_at),
      rowActions(
        c.status !== "revoked" && rowButton("复制", () => showCodeCopies(c.id)),
        rowButton("改备注", askText({ title: "改备注", label: "备注", value: c.note }, (note) => api("PATCH", wsPath("/codes/" + c.id), { note }), "已保存")),
        c.expires_at && rowButton("改期限", askText({
          title: "改期限", message: "不影响已连接的设备。", label: "从现在起的有效时长，如 30m、24h、7d", value: "24h",
        }, (duration) => api("PATCH", wsPath("/codes/" + c.id), { duration }), "已保存")),
        c.status !== "revoked" && rowButton("撤销", ask("撤销这个 Code？用它进来的设备会被立即断开，且不能再连接。", () => api("POST", wsPath("/codes/" + c.id + "/revoke")), "已撤销", { confirmLabel: "撤销" }), { danger: true }),
        rowButton("删除", ask("删除这条记录？如果 Code 还有效，也会一并撤销，用它进来的设备会被断开。", () => api("DELETE", wsPath("/codes/" + c.id)), "已删除", { confirmLabel: "删除" }), { danger: true })),
    ]),
    "还没有生成过 Code");
}

const CODE_KINDS = {
  once: { label: "一次性", max: 1 },
  timed: { label: "限时（到期前不限次数）", duration: true },
  both: { label: "限时限次", max: true, duration: true },
  permanent: { label: "永久（适合无人值守的机器）" },
};

function viewCodes() {
  const kind = select({
    id: "code-kind", onchange: () => sync(),
    options: Object.entries(CODE_KINDS).map(([value, choice]) => ({ value, label: choice.label })),
  });
  const duration = input({ id: "code-duration", value: "24h", placeholder: "30m、24h、7d" });
  const maxUses = input({ id: "code-max", type: "number", min: "1", value: "3" });
  const durationField = field("有效时长", duration);
  const maxField = field("最多使用次数", maxUses, { hint: "每次运行算一次" });
  const note = input({ id: "code-note", placeholder: "发给谁、做什么用" });
  function sync() {
    const choice = CODE_KINDS[kind.value];
    durationField.hidden = !choice.duration;
    maxField.hidden = choice.max !== true;
  }
  sync();
  const holder = el("div", {});
  const drawList = () => holder.replaceChildren(list("codes", (query) => api("GET", wsPath("/codes?" + query)), codeRows));
  drawList();
  const form = formOf({ id: "code-form" }, async () => {
    const choice = CODE_KINDS[kind.value];
    const body = { note: note.value };
    if (choice.duration) body.duration = duration.value;
    if (choice.max === true) body.max_uses = Number(maxUses.value);
    else if (choice.max) body.max_uses = choice.max;
    const created = await api("POST", wsPath("/codes"), body);
    note.value = "";
    drawList();
    await showCodeCopies(created.id);
  },
    field("类型", kind), durationField, maxField, field("备注", note),
    formActions(submitButton("生成")));
  return [
    card("生成 Code", {}, form),
    card("已生成的 Code", {}, holder),
  ];
}

function banRows(items, remove) {
  return dataTable(["类型", "内容", "备注", "到期", "时间", "操作"],
    items.map((b) => [
      b.kind === "ip" ? "IP" : "设备",
      monoCell(b.kind === "ip" ? b.value : short(b.value), b.value),
      cell(b.note || "—", { wrap: true }),
      b.expires_at ? time(b.expires_at) : "永久",
      time(b.created_at),
      rowActions(rowButton("解除", ask("解除这条拉黑？", () => remove(b.id), "已解除", { danger: false, confirmLabel: "解除" }))),
    ]),
    "黑名单是空的");
}

function banForm(submit, explanation) {
  const value = input({ id: "ban-value", mono: true, required: true, placeholder: "203.0.113.7 或 198.51.100.0/24" });
  const kind = select({
    id: "ban-kind",
    options: [{ value: "ip", label: "IP 或网段" }, { value: "device", label: "设备 ID" }],
    onchange: (next) => { value.placeholder = next === "ip" ? "203.0.113.7 或 198.51.100.0/24" : "64 位设备 ID"; },
  });
  const note = input({ id: "ban-note" });
  const duration = input({ id: "ban-duration", placeholder: "留空为永久，或 30m、24h、7d" });
  return card("添加黑名单", { hint: explanation },
    formOf({ id: "ban-form" }, changes(() => submit({ kind: kind.value, value: value.value, note: note.value, duration: duration.value }), "已拉黑"),
      field("类型", kind), field("内容", value), field("备注", note), field("时长", duration),
      formActions(submitButton("拉黑"))));
}

function viewBans() {
  return [
    banForm((body) => api("POST", wsPath("/bans"), body),
      "立即断开匹配的连接，只在这个工作区生效。拉黑 IP 会影响同一出口后的所有人。设备 ID 由客户端上报，克隆的系统可能共用同一个 ID。"),
    card("黑名单", {},
      list("bans", (query) => api("GET", wsPath("/bans?" + query)),
        (items) => banRows(items, (id) => api("DELETE", wsPath("/bans/" + id))))),
  ];
}

function viewConnections() {
  return card("连接历史", {},
    list("connections", (query) => api("GET", wsPath("/connections?" + query)), (items) =>
      dataTable(["主机名", "虚拟 IP", "来源 IP", "设备", "上线", "下线", "收 / 发"],
        items.map((c) => [
          c.hostname,
          monoCell(c.ip),
          monoCell(c.peer),
          monoCell(c.device ? short(c.device) : "—", c.device ?? ""),
          time(c.started_at),
          c.ended_at ? time(c.ended_at) : badge("在线", "success"),
          c.ended_at ? bytes(c.rx_bytes) + " / " + bytes(c.tx_bytes) : "—",
        ]),
        "还没有连接记录")));
}

function auditRows(items) {
  return dataTable(["时间", "操作者", "动作", "对象", "来源"],
    items.map((a) => [
      time(a.at),
      a.actor,
      ACTIONS[a.action] ?? a.action,
      cell(a.target || "—", { mono: true, wrap: true }),
      monoCell(a.source || "—", "代理上报的来源，仅供参考"),
    ]),
    "还没有记录");
}

function viewAudit() {
  return card("审计", {},
    list("audit", (query) => api("GET", wsPath("/audit?" + query)), auditRows));
}

function showToken(name, token) {
  sheet({ title: "复制 Token" }, secretRow({ label: name, secret: token }));
}

function tokensSection(items, create, remove, reveal, explanation) {
  const name = input({ id: "token-name", required: true, placeholder: "用途，如 ci" });
  const duration = input({ id: "token-duration", placeholder: "留空为永久，或 30m、24h、7d" });
  return [
    card("创建 Token", { hint: explanation },
      formOf({ id: "token-form" }, async () => {
        const created = await create({ name: name.value, duration: duration.value });
        await refresh();
        showToken(created.name, created.token);
      },
        field("名称", name), field("有效时长", duration),
        formActions(submitButton("创建")))),
    card("Token", {},
      dataTable(["名称", "创建时间", "到期", "最后使用", "操作"],
        items.map((t) => [
          t.name,
          time(t.created_at),
          t.expires_at ? time(t.expires_at) : "永久",
          time(t.last_used),
          rowActions(
            rowButton("复制", async () => showToken(t.name, (await reveal(t.id)).token)),
            rowButton("删除", ask("删除这个 Token？用它的脚本会立即失效。", () => remove(t.id), "已删除", { confirmLabel: "删除" }), { danger: true })),
        ]),
        "还没有 Token")),
  ];
}

async function viewTokens() {
  const items = await api("GET", wsPath("/tokens"));
  return tokensSection(items, (body) => api("POST", wsPath("/tokens"), body), (id) => api("DELETE", wsPath("/tokens/" + id)),
    (id) => api("GET", wsPath("/tokens/" + id + "/secret")),
    "脚本用 Authorization: Bearer 调用接口。权限等同这个工作区的普通管理员，不能增删管理员。");
}

async function viewAdmins() {
  const items = await api("GET", wsPath("/admins"));
  const username = input({ id: "admin-name", required: true });
  const password = input({ id: "admin-password", type: "password", autocomplete: "new-password" });
  const role = select({ id: "admin-role", options: [{ value: "admin", label: "管理员" }, { value: "owner", label: "owner" }] });
  const canAttach = myWorkspace()?.standing === "super";
  const attach = checkbox("使用已有账号（不用填密码）", { id: "admin-attach" });
  return [
    card("添加管理员", { hint: "只有 owner 能增删管理员。工作区至少保留一个 owner。" },
      formOf({ id: "admin-form" }, changes(() => {
        const body = { username: username.value, role: role.value };
        if (!canAttach || !attach.input.checked) body.password = password.value;
        return api("POST", wsPath("/admins"), body);
      }, "已添加"),
        field("用户名", username),
        field("初始密码", password, { hint: "首次登录时必须修改" }),
        field("角色", role),
        canAttach ? attach : null,
        formActions(submitButton("添加")))),
    card("管理员", {},
      dataTable(["用户名", "角色", "操作"],
        items.map((a) => [
          [a.username, a.shared ? el("span", { class: "muted" }, "（也属于其他工作区）") : null],
          badge(ROLE[a.role], ROLE_TONE[a.role]),
          rowActions(
            rowButton(a.role === "owner" ? "设为管理员" : "设为 owner", changes(() => api("PATCH", wsPath("/admins/" + a.user_id), { role: a.role === "owner" ? "admin" : "owner" }), "已修改")),
            rowButton("重置密码", askNewPassword(wsPath("/admins/" + a.user_id + "/password"))),
            rowButton("移除", ask("移除 " + a.username + "？", () => api("DELETE", wsPath("/admins/" + a.user_id)), "已移除", { confirmLabel: "移除" }), { danger: true })),
        ]),
        "还没有管理员")),
  ];
}

// ---- System views ----

async function viewWorkspaces() {
  const all = await api("GET", "workspaces");
  const name = input({ id: "ws-name", required: true });
  const cidr = input({ id: "ws-cidr", mono: true, required: true, value: all.suggested_cidr });
  const owner = input({ id: "ws-owner", placeholder: "可选" });
  const ownerPassword = input({ id: "ws-owner-password", type: "password", autocomplete: "new-password", placeholder: "首次登录时必须修改" });
  return [
    card("创建工作区", { hint: "每个工作区一张组网，相互隔离，网段可以重叠。owner 留空时可以稍后添加；填已有账号且不填密码，会把这个账号加进来。" },
      formOf({ id: "workspace-form" }, async () => {
        const body = { name: name.value, cidr: cidr.value };
        if (owner.value.trim()) {
          body.owner_username = owner.value;
          if (ownerPassword.value) body.owner_password = ownerPassword.value;
        }
        await api("POST", "workspaces", body);
        toast("已创建", "success");
        await boot();
      },
        field("名称", name), field("网段（/20 到 /30）", cidr), field("owner 用户名", owner), field("owner 初始密码", ownerPassword),
        formActions(submitButton("创建")))),
    card("工作区", {},
      dataTable(["名称", "网段", "在线", "累计收 / 发", "创建时间", "操作"],
        all.items.map((w) => [
          w.name,
          monoCell(w.cidr),
          (w.stats?.online ?? 0) + " / " + (w.stats?.capacity ?? 0),
          bytes(w.stats?.rx_bytes) + " / " + bytes(w.stats?.tx_bytes),
          time(w.created_at),
          rowActions(
            rowButton("改名", askText({ title: "改名", label: "新名称", value: w.name },
              (value) => api("PATCH", "workspaces/" + w.id, { name: value }), "已改名", boot)),
            rowButton("改网段", askText({ title: "改网段", message: "所有成员会断开，重连后拿到新地址。", label: "新网段", value: w.cidr },
              (value) => api("PATCH", "workspaces/" + w.id, { cidr: value }), "已修改网段", boot)),
            rowButton("删除", askText({
              title: "删除工作区",
              message: "删除工作区会断开所有成员，并删除它的 Code、记录和只属于它的账号，不能恢复。",
              label: "输入工作区名称确认",
              placeholder: w.name,
              danger: true,
              confirmLabel: "删除",
              ready: (value) => value === w.name,
            }, () => api("DELETE", "workspaces/" + w.id, {}), "已删除", boot), { danger: true })),
        ]),
        "还没有工作区，先创建一个")),
  ];
}

async function viewUsers() {
  const [users, workspaces] = await Promise.all([api("GET", "users"), api("GET", "workspaces")]);
  const nameOf = (id) => workspaces.items.find((w) => w.id === id)?.name ?? "?";
  return card("账号", { hint: "普通账号在工作区的“管理员”页添加。" },
    dataTable(["用户名", "身份", "工作区", "待改密码", "创建时间", "操作"],
      users.map((u) => [
        u.username,
        u.is_super ? "超管" : "管理员",
        cell(u.workspaces.map(([id, role]) => nameOf(id) + "（" + ROLE[role] + "）").join("，") || "—", { wrap: true }),
        u.must_change_password ? "是" : "否",
        time(u.created_at),
        u.is_super ? "" : rowActions(
          rowButton("重置密码", askNewPassword("users/" + u.id + "/password")),
          rowButton("删除", ask("删除账号 " + u.username + "？", () => api("DELETE", "users/" + u.id), "已删除", { confirmLabel: "删除" }), { danger: true })),
      ]),
      "没有账号"));
}

function viewGlobalBans() {
  return [
    banForm((body) => api("POST", "bans", body),
      "对所有工作区生效。拉黑的 IP 在 TLS 之前就被丢弃。"),
    card("全局黑名单", {},
      list("sbans", (query) => api("GET", "bans?" + query),
        (items) => banRows(items, (id) => api("DELETE", "bans/" + id)))),
  ];
}

function viewGlobalAudit() {
  return card("全局审计", {},
    list("saudit", (query) => api("GET", "audit?" + query), auditRows));
}

async function viewGlobalTokens() {
  const items = await api("GET", "tokens");
  return tokensSection(items, (body) => api("POST", "tokens", body), (id) => api("DELETE", "tokens/" + id),
    (id) => api("GET", "tokens/" + id + "/secret"),
    "权限等同超管，可以访问 /metrics。请妥善保管。");
}

async function viewSettings() {
  const settings = await api("GET", "settings");
  const addr = input({ id: "set-addr", mono: true, value: settings.public_addr ?? settings.suggested_public_addr });
  const listen = input({ id: "set-listen", mono: true, value: settings.relay_listen ?? settings.suggested_relay_listen });
  const days = input({ id: "set-days", type: "number", min: "1", value: String(settings.history_days) });
  return card("服务设置", {},
    settings.relay_listening_on
      ? notice("中继正在监听 " + settings.relay_listening_on, "ok")
      : notice("中继没有在监听，请检查监听地址", "warn"),
    formOf({ id: "settings-form", layout: "stack" }, changes(() => api("PUT", "settings", {
      public_addr: addr.value, relay_listen: listen.value, history_days: Number(days.value),
    }), "已保存"),
      field("对外地址", addr, { hint: "写进新 Code，已发出的 Code 仍指向旧地址" }),
      field("中继监听地址", listen, { hint: "修改时已连接的成员不受影响" }),
      field("连接历史和审计保留天数", days),
      formActions(submitButton("保存"))));
}

async function viewMe() {
  const [sessions, keys] = await Promise.all([api("GET", "me/sessions"), api("GET", "me/ssh-keys")]);
  const keyName = input({ id: "ssh-key-name", placeholder: "留空时用公钥里的备注" });
  const keyText = input({ id: "ssh-key-text", mono: true, required: true, placeholder: "ssh-ed25519 AAAA…" });
  const password = input({ id: "my-password", type: "password", autocomplete: "new-password" });
  return [
    card("修改密码", {},
      formOf({ id: "my-password-form", layout: "stack" }, changes(() => api("POST", "me/password", { password: password.value }), "已修改，其他登录已退出"),
        field("新密码", password),
        formActions(submitButton("保存")))),
    card("SSH 公钥", { hint: "添加后，复制 Code 时会多出每个公钥的联合 Code。对方粘贴联合 Code 后，持有对应私钥的人能远程控制对方电脑。这里只存公钥，私钥请留在自己手里。" },
      formOf({ id: "ssh-key-form" }, changes(() => api("POST", "me/ssh-keys", { name: keyName.value, public_key: keyText.value }), "已添加"),
        field("名称", keyName),
        field("公钥（.pub 文件的内容）", keyText, { wide: true }),
        formActions(submitButton("添加"))),
      dataTable(["名称", "指纹", "添加时间", "操作"],
        keys.map((k) => [
          k.name,
          monoCell(k.fingerprint),
          time(k.created_at),
          rowActions(rowButton("删除", ask("删除公钥 " + k.name + "？已经发出去的联合 Code 不受影响。", () => api("DELETE", "me/ssh-keys/" + k.id), "已删除", { confirmLabel: "删除" }), { danger: true })),
        ]),
        "还没有添加公钥")),
    card("登录中的会话", {},
      dataTable(["设备", "登录时间", "最近活动", "操作"],
        sessions.map((s) => [
          cell(s.user_agent || "—", { wrap: true }),
          time(s.created_at),
          time(s.last_seen),
          rowActions(rowButton("结束", changes(() => api("DELETE", "me/sessions/" + s.id), "已结束"), { danger: true })),
        ]),
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
