"use strict";
// The public download page: every client this server carries, with the one for this
// computer up front. Works before anyone logs in.

const ROWS = [
  { os: "windows", name: "Windows", note: "双击运行，同意 UAC" },
  { os: "macos", name: "macOS", note: "解压后打开，输入系统密码" },
  { os: "linux", name: "Linux 桌面", note: "通过 pkexec 授权" },
  { os: "linux-cli", name: "Linux 无界面", note: "命令行客户端，静态链接" },
];
const CPUS = [["x64", "x86-64"], ["arm64", "ARM"]];

// Same rules as the website. Anything unrecognised, such as a phone, gets no suggestion:
// there is no build to offer it.
function detectOs() {
  const text = (navigator.userAgent + " " + (navigator.platform || "")).toLowerCase();
  if (/android|iphone|ipad|ipod/.test(text)) return null;
  // iPadOS asks for desktop sites and calls itself a Mac; only touch gives it away.
  if (text.includes("mac") && navigator.maxTouchPoints > 1) return null;
  if (text.includes("windows") || text.includes("win32")) return "windows";
  if (text.includes("mac")) return "macos";
  if (text.includes("linux")) return "linux";
  return null;
}

// Browsers on Macs always claim Intel, and most Macs in use are not.
function guessCpu(os) {
  const text = (navigator.userAgent + " " + (navigator.platform || "")).toLowerCase();
  if (/aarch64|arm64/.test(text) || os === "macos") return "arm64";
  return "x64";
}

function suggestion(client, row) {
  return el("div", { class: "dl-suggest" },
    el("a", { class: "btn btn-primary dl-main", id: "dl-main", href: "downloads/" + client.file, download: client.file },
      "下载 " + row.name + (row.os === "linux" ? "版（" : " 版（") + client.arch + "）"),
    el("span", { class: "muted" }, bytes(client.size) + " · " + client.file));
}

function matrix(clients, os, cpu) {
  const cell = (row, key) => {
    const client = clients.find((c) => c.os === row.os && c.cpu === key);
    if (!client) return el("span", { class: "dl-none" }, "—");
    return el("a", {
      class: cx("dl-cell", row.os === os && key === cpu && "is-current"),
      href: "downloads/" + client.file, download: client.file, title: client.file,
    }, el("strong", {}, client.arch), el("span", {}, bytes(client.size)));
  };
  return el("div", { class: "dl-matrix", id: "dl-matrix" },
    el("div", { class: "dl-line dl-head" },
      el("span", {}, "平台"), CPUS.map(([, label]) => el("span", {}, label)), el("span", {}, "说明")),
    ROWS.filter((row) => clients.some((c) => c.os === row.os)).map((row) =>
      el("div", { class: cx("dl-line", row.os === os && "is-current") },
        el("div", { class: "dl-platform" }, el("strong", {}, row.name), row.os === os && el("span", { class: "dl-tag" }, "当前系统")),
        CPUS.map(([key]) => cell(row, key)),
        el("span", { class: "muted dl-note" }, row.note))));
}

function draw(catalog, os, cpu) {
  const { site, version, clients } = catalog;
  const best = clients.find((c) => c.os === os && c.cpu === cpu);
  const row = ROWS.find((r) => r.os === os);
  document.getElementById("root").replaceChildren(el("div", { class: "dl-page" },
    el("header", { class: "dl-top" },
      el("a", { href: "./", class: "dl-home" }, logo()),
      el("a", { href: "./", class: "muted" }, "管理后台 →")),
    el("section", { class: "dl-hero" },
      el("h1", {}, "下载 varco 客户端"),
      el("p", { class: "muted" }, "一个文件，不用安装。打开后粘贴管理员发来的 Code 就能入网。"),
      best && suggestion(best, row)),
    clients.length
      ? el("section", {},
        el("h2", { class: "dl-title" }, "全部版本", el("span", { class: "muted" }, "版本 " + version)),
        matrix(clients, os, cpu))
      : el("p", { class: "notice notice-warn" }, "这台服务端没有附带客户端，请到官网下载。"),
    el("p", { class: "dl-more" },
      el("a", { href: site, target: "_blank", rel: "noopener noreferrer" }, "官网和使用说明 ↗"))));
}

async function start() {
  const response = await fetch("api/downloads");
  if (!response.ok) throw new Error("请求失败（" + response.status + "）");
  const catalog = await response.json();
  const os = detectOs();
  const cpu = guessCpu(os);
  draw(catalog, os, cpu);
  // Chromium hides the real architecture from the user agent but will tell if asked.
  if (!os || !navigator.userAgentData?.getHighEntropyValues) return;
  const { architecture } = await navigator.userAgentData.getHighEntropyValues(["architecture"]);
  const real = { arm: "arm64", x86: "x64" }[architecture];
  if (real && real !== cpu) draw(catalog, os, real);
}

start().catch((error) => {
  document.getElementById("root").replaceChildren(
    el("div", { class: "dl-page" }, el("p", { class: "notice notice-warn" }, error.message)));
});
