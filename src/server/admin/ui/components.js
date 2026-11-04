"use strict";
// The console's component library. It knows nothing about the API or the views.
//
// Hostnames, notes and names come from clients and other people, so all text goes
// in through textContent: el() has no way to set HTML. The CSP allows neither images
// nor style attributes, so icons are built as SVG nodes and positions go through
// node.style, which it does allow.

const cx = (...names) => names.filter(Boolean).join(" ");
let uid = 0;

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on")) node[key] = value;
    else if (key === "class") node.className = value;
    else if (key === "value") node.value = value;
    else if (key === "hidden" || key === "disabled" || key === "required" || key === "checked") node[key] = true;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false) node.append(child);
  }
  return node;
}

function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  node.append(...children);
  return node;
}

function bytes(count) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = count ?? 0, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return (unit === 0 ? value : value.toFixed(1)) + " " + units[unit];
}

// ---- Icons and logo ----

const ICONS = {
  chevron: "M6 9l6 6 6-6",
  check: "M5 12l5 5 9-10",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-4.3-4.3",
  settings: "M4 6h9M18 6h2M4 12h2M11 12h9M4 18h7M16 18h4M15.5 3.5v5M8.5 9.5v5M13.5 15.5v5",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  layers: "M12 3l9 5-9 5-9-5zM3 13l9 5 9-5",
  inbox: "M3 13h5l2 3h4l2-3h5M5.5 5h13L21 13v6H3v-6z",
};

function icon(name) {
  return svg("svg", { class: "icon", viewBox: "0 0 24 24", "aria-hidden": "true" }, svg("path", { d: ICONS[name] }));
}

// The mark from site/favicon.svg. Its square follows the theme so it stays visible
// on a dark header.
function logo() {
  return el("span", { class: "logo" },
    svg("svg", { class: "logo-mark", viewBox: "0 0 32 32", "aria-hidden": "true" },
      svg("rect", { class: "logo-square", width: "32", height: "32", rx: "7" }),
      svg("path", { class: "logo-v", d: "M8 9l8 15 8-15" }),
      svg("circle", { class: "logo-dot", cx: "16", cy: "9", r: "2.4" })),
    el("span", { class: "logo-word" }, "varco"));
}

// ---- Toast ----

let toastTimer;
function toast(message, tone = "info") {
  const box = document.getElementById("toast");
  box.textContent = message;
  box.className = "toast-" + tone;
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { box.hidden = true; }, 4000);
}

// ---- Buttons ----

function setBusy(node, busy) {
  if (!node) return;
  node.disabled = busy;
  node.classList.toggle("is-busy", busy);
  if (busy) node.setAttribute("aria-busy", "true");
  else node.removeAttribute("aria-busy");
}

// An onclick that returns a promise keeps the button spinning and disabled until it
// settles, and a failure ends up in a toast.
function button(label, { variant, size, icon: iconName, onclick, type = "button", id, title, disabled } = {}) {
  const node = el("button", {
    type, id, title, disabled,
    class: cx("btn", variant && "btn-" + variant, size === "sm" && "btn-sm"),
  }, iconName && icon(iconName), label && el("span", {}, label));
  if (onclick) {
    node.onclick = async (event) => {
      let spinning = false;
      try {
        const result = onclick(event);
        if (result?.then) {
          spinning = true;
          setBusy(node, true);
          await result;
        }
      } catch (error) {
        toast(error.message, "error");
      } finally {
        if (spinning) setBusy(node, false);
      }
    };
  }
  return node;
}

const submitButton = (label) => button(label, { type: "submit", variant: "primary" });
const rowButton = (label, onclick, { danger } = {}) =>
  button(label, { size: "sm", variant: danger ? "ghost-danger" : "ghost", onclick });

// ---- Form controls ----

function input({ mono, ...props } = {}) {
  return el("input", { class: cx("input", mono && "mono"), ...props });
}

function field(label, control, { hint } = {}) {
  return el("label", { class: "field" },
    el("span", { class: "field-label" }, label),
    control,
    hint && el("span", { class: "field-hint" }, hint));
}

// The box is at node.input.
function checkbox(label, { id } = {}) {
  const box = el("input", { type: "checkbox", id, class: "checkbox" });
  const node = el("label", { class: "check" }, box, el("span", {}, label));
  node.input = box;
  return node;
}

// Runs the action with the submit button spinning; a failure ends up in a toast.
function formOf({ id }, action, ...children) {
  let busy = false;
  return el("form", { id, class: "form-stack", onsubmit: async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    const submit = event.target.querySelector("[type=submit]");
    setBusy(submit, true);
    try {
      await action();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      busy = false;
      setBusy(submit, false);
    }
  } }, ...children);
}

const formActions = (...children) => el("div", { class: "form-actions" }, ...children);

// ---- Floating layer: what dropdowns and menus open in ----

let activeLayer = null;

function closeFloating() {
  activeLayer?.close();
}

// Lives under body and is fixed in place, so a scrolling table can't clip it.
// Returns the function that closes it.
function floating(anchor, content, { align = "start", matchWidth = false, onclose } = {}) {
  closeFloating();
  const layer = el("div", { class: "floating" }, content);
  // A modal dialog sits above everything under body, so a menu it opens must live in it.
  (activeDialog?.node ?? document.body).append(layer);

  const gap = 4, margin = 8;
  const rect = anchor.getBoundingClientRect();
  if (matchWidth) layer.style.minWidth = rect.width + "px";
  const below = innerHeight - rect.bottom - gap - margin;
  const above = rect.top - gap - margin;
  const height = layer.offsetHeight;
  const up = height > below && above > below;
  layer.style.maxHeight = (up ? above : below) + "px";
  layer.style.top = (up ? rect.top - gap - Math.min(height, above) : rect.bottom + gap) + "px";
  const width = layer.offsetWidth;
  const left = align === "end" ? rect.right - width : rect.left;
  layer.style.left = Math.max(margin, Math.min(left, innerWidth - width - margin)) + "px";

  const onPointer = (event) => {
    if (!layer.contains(event.target) && !anchor.contains(event.target)) close();
  };
  const onScroll = (event) => {
    if (!layer.contains(event.target)) close();
  };
  const onKey = (event) => {
    if (event.key === "Escape") {
      // Closes the menu only, not a dialog it is in.
      event.preventDefault();
      close();
      anchor.focus();
    }
  };
  function close() {
    document.removeEventListener("pointerdown", onPointer, true);
    document.removeEventListener("scroll", onScroll, true);
    document.removeEventListener("keydown", onKey, true);
    removeEventListener("resize", close);
    layer.remove();
    activeLayer = null;
    onclose?.();
  }
  document.addEventListener("pointerdown", onPointer, true);
  document.addEventListener("scroll", onScroll, true);
  document.addEventListener("keydown", onKey, true);
  addEventListener("resize", close);
  activeLayer = { close };
  return close;
}

// The chosen value is the button's own .value, so forms read it like an input's.
// options: [{ value, label }]; onchange gets the new value.
function select({ id, options, value, onchange, disabled }) {
  const listId = "select-" + ++uid;
  const text = el("span", { class: "select-value" });
  const node = el("button", {
    type: "button", id, disabled, class: "select", role: "combobox",
    "aria-haspopup": "listbox", "aria-expanded": "false", "aria-controls": listId,
  }, text, icon("chevron"));
  let close = null, rows = [], active = 0, swallowSpace = false;

  const setValue = (next) => {
    node.value = next;
    text.textContent = options.find((option) => option.value === next)?.label ?? "";
  };
  setValue(value ?? options[0]?.value);

  function highlight(index) {
    active = index;
    rows.forEach((row, n) => row.classList.toggle("is-active", n === index));
    node.setAttribute("aria-activedescendant", rows[index].id);
    rows[index].scrollIntoView({ block: "nearest" });
  }

  function choose(index) {
    const next = options[index].value;
    const changed = next !== node.value;
    setValue(next);
    close?.();
    if (changed) onchange?.(next);
  }

  function open() {
    rows = options.map((option, index) => {
      const chosen = option.value === node.value;
      return el("div", {
        role: "option", id: listId + "-" + index, class: "option", "aria-selected": String(chosen),
        onclick: () => choose(index),
        onpointermove: () => { if (active !== index) highlight(index); },
      }, el("span", { class: "option-label" }, option.label), chosen && icon("check"));
    });
    // Keeping focus on the button is what keeps the keys below working.
    const list = el("div", { class: "menu", role: "listbox", id: listId, onpointerdown: (event) => event.preventDefault() }, rows);
    close = floating(node, list, { matchWidth: true, onclose: () => {
      close = null;
      node.setAttribute("aria-expanded", "false");
      node.removeAttribute("aria-activedescendant");
    } });
    node.setAttribute("aria-expanded", "true");
    highlight(Math.max(0, options.findIndex((option) => option.value === node.value)));
  }

  node.onclick = () => { if (close) close(); else open(); };
  node.onkeydown = (event) => {
    if (!close) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        open();
      }
      return;
    }
    const last = rows.length - 1;
    const moves = { ArrowDown: Math.min(active + 1, last), ArrowUp: Math.max(active - 1, 0), Home: 0, End: last };
    if (event.key in moves) {
      event.preventDefault();
      highlight(moves[event.key]);
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      swallowSpace = event.key === " ";
      choose(active);
    } else if (event.key === "Tab") {
      close();
    } else if (event.key.length === 1) {
      const letter = event.key.toLowerCase();
      const count = options.length;
      for (let step = 1; step <= count; step += 1) {
        const index = (active + step) % count;
        if (options[index].label.toLowerCase().startsWith(letter)) {
          highlight(index);
          break;
        }
      }
    }
  };
  // Without this, letting go of the space that chose an option would reopen the list.
  node.onkeyup = (event) => {
    if (event.key === " " && swallowSpace) {
      event.preventDefault();
      swallowSpace = false;
    }
  };
  return node;
}

// groups: [{ title, scroll, items: [{ label, icon, hint, checked, id, onselect }] }]
function dropdownMenu(trigger, groups) {
  let close = null;
  trigger.setAttribute("aria-haspopup", "menu");
  trigger.setAttribute("aria-expanded", "false");

  function open(focusFirst) {
    const items = [];
    const menu = el("div", { class: "menu", role: "menu", tabindex: "-1" },
      groups.filter(Boolean).map((group) => el("div", { class: "menu-group", role: "group" },
        group.title && el("div", { class: "menu-title" }, group.title),
        el("div", { class: group.scroll ? "menu-scroll" : "" }, group.items.map((item) => {
          const node = el("button", {
            type: "button", id: item.id, class: "option", role: "menuitem", tabindex: "-1",
            onclick: () => { close?.(); item.onselect(); },
          },
            item.icon && icon(item.icon),
            el("span", { class: "option-label" }, item.label),
            item.hint && el("span", { class: "option-hint" }, item.hint),
            item.checked && icon("check"));
          items.push(node);
          return node;
        }))),
      ));
    menu.onkeydown = (event) => {
      const at = items.indexOf(document.activeElement);
      const last = items.length - 1;
      const moves = {
        ArrowDown: at >= last ? 0 : at + 1, ArrowUp: at <= 0 ? last : at - 1, Home: 0, End: last,
      };
      if (event.key in moves) {
        event.preventDefault();
        items[moves[event.key]].focus();
      } else if (event.key === "Tab") {
        close?.();
      }
    };
    close = floating(trigger, menu, { align: "end", onclose: () => {
      close = null;
      trigger.setAttribute("aria-expanded", "false");
    } });
    trigger.setAttribute("aria-expanded", "true");
    if (focusFirst) items[0]?.focus();
    else menu.focus();
  }

  // A click from the keyboard has detail 0; only then does an item take the highlight.
  trigger.onclick = (event) => { if (close) close(); else open(event.detail === 0); };
  trigger.onkeydown = (event) => {
    if (!close && event.key === "ArrowDown") {
      event.preventDefault();
      open(true);
    }
  };
  return trigger;
}

// ---- Dialogs ----

let activeDialog = null;

// Stays open while the action runs and shows a failure inline, so what was typed
// isn't lost. `after` runs once it has closed. With a control, the action gets its
// value, and `ready` can hold the confirm button back until the value is acceptable.
function dialog({ title, message, control, confirmLabel = "确定", danger, ready, action, after }) {
  closeOverlays();
  const error = el("p", { class: "dialog-error", role: "alert", hidden: true });
  const confirm = button(confirmLabel, { type: "submit", variant: danger ? "danger" : "primary" });
  let busy = false;

  function close() {
    closeFloating();
    node.close();
    node.remove();
    activeDialog = null;
  }

  const form = el("form", { class: "dialog-form", onsubmit: async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    error.hidden = true;
    setBusy(confirm, true);
    try {
      await action(control?.querySelector("input").value);
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
      busy = false;
      setBusy(confirm, false);
      return;
    }
    close();
    after?.();
  } },
    title && el("h2", { class: "dialog-title" }, title),
    message && el("p", { class: "dialog-message" }, message),
    control,
    error,
    el("div", { class: "dialog-actions" },
      button("取消", { onclick: () => { if (!busy) close(); } }),
      confirm));

  const node = el("dialog", {
    class: "dialog",
    oncancel: (event) => {
      event.preventDefault();
      if (!busy) close();
    },
    // Only a click on the backdrop lands on the dialog itself.
    onclick: (event) => { if (event.target === node && !busy) close(); },
  }, form);

  const box = control?.querySelector("input");
  if (box && ready) {
    const sync = () => { confirm.disabled = !ready(box.value); };
    box.oninput = sync;
    sync();
  }
  document.body.append(node);
  node.showModal();
  activeDialog = { close, node };
  const first = control && [...control.querySelectorAll("input")].find((one) => !one.disabled && one.offsetParent);
  if (first) {
    first.focus();
    first.select();
  }
}

// A dialog with several fields; `fields` may hold gaps for ones that don't apply.
function formDialog({ fields, ...rest }) {
  dialog({ ...rest, control: el("div", { class: "dialog-fields" }, fields) });
}

// For reading and copying: nothing to confirm, so the only button closes it.
function sheet({ title }, ...body) {
  closeOverlays();
  function close() {
    closeFloating();
    node.close();
    node.remove();
    activeDialog = null;
  }
  const node = el("dialog", {
    class: "dialog dialog-wide",
    oncancel: (event) => {
      event.preventDefault();
      close();
    },
    onclick: (event) => { if (event.target === node) close(); },
  }, el("div", { class: "dialog-form" },
    el("h2", { class: "dialog-title" }, title),
    ...body,
    el("div", { class: "dialog-actions" }, button("关闭", { onclick: close }))));
  document.body.append(node);
  node.showModal();
  activeDialog = { close, node };
}

function closeOverlays() {
  closeFloating();
  activeDialog?.close();
}

// ---- Layout ----

function card(title, { hint, action } = {}, ...body) {
  return el("section", { class: "card" },
    title && el("div", { class: "card-head" }, el("h2", { class: "card-title" }, title), action),
    el("div", { class: "card-body" }, ...body),
    hint && el("p", { class: "card-hint" }, hint));
}

function authPage(title, description, ...body) {
  return el("div", { class: "auth" },
    logo(),
    el("section", { class: "card auth-card" },
      el("h1", { class: "auth-title" }, title),
      description && el("p", { class: "muted" }, description),
      ...body));
}

const stats = (...items) => el("div", { class: "stats" }, ...items);

function stat(label, value, unit) {
  return el("div", { class: "stat" },
    el("div", { class: "stat-label" }, label),
    el("div", { class: "stat-value" }, value, unit && el("span", { class: "stat-unit" }, unit)));
}

const badge = (text, tone = "neutral") => el("span", { class: "badge badge-" + tone }, text);
const notice = (text, tone) => el("p", { class: "notice notice-" + tone }, text);

// items: [key, label, { end }]; `end` sets a tab apart at the far side.
function tabs(items, active, onchange) {
  return el("nav", { class: "tabs" }, items.map(([key, label, { end } = {}]) => el("button", {
    type: "button", class: cx("tab", end && "tab-end", key === active && "is-active"), "data-tab": key,
    "aria-current": key === active ? "page" : null,
    onclick: () => onchange(key),
  }, label)));
}

// ---- Tables ----

function emptyState(text) {
  return el("div", { class: "empty" }, icon("inbox"), el("span", {}, text));
}

const cell = (content, { mono, wrap, title } = {}) =>
  el("td", { class: cx(mono && "mono", wrap && "cell-wrap"), title }, content);
const monoCell = (content, title) => cell(content, { mono: true, title });

function rowActions(...buttons) {
  return el("td", { class: "cell-actions" }, el("div", { class: "row-actions" }, ...buttons));
}

// Each row is an array of cells: a <td> from the helpers above, or plain content.
function dataTable(headers, rows, empty) {
  if (!rows.length) return emptyState(empty);
  return el("div", { class: "table-wrap" }, el("table", { class: "table" },
    el("thead", {}, el("tr", {}, headers.map((header) => el("th", { class: header === "操作" ? "th-actions" : null }, header)))),
    el("tbody", {}, rows.map((row) => el("tr", {},
      row.map((content) => content instanceof HTMLTableCellElement ? content : el("td", {}, content)))))));
}

// ---- A list with search and paging ----

const PAGE = 50;

function searchBox(value, oninput) {
  return el("label", { class: "search" }, icon("search"),
    el("input", { class: "input", type: "search", placeholder: "搜索", "aria-label": "搜索", value, oninput }));
}

// state ({ q, offset }) belongs to the caller, so the list keeps its place across redraws.
function pagedList(state, load, render) {
  const body = el("div", {});
  const pager = el("div", { class: "pager" });
  async function draw() {
    const query = new URLSearchParams({ q: state.q, limit: PAGE, offset: state.offset });
    try {
      const page = await load(query.toString());
      body.replaceChildren(render(page.items));
      pager.replaceChildren(...(page.total > PAGE ? [
        button("上一页", { size: "sm", disabled: state.offset === 0, onclick: () => { state.offset = Math.max(0, state.offset - PAGE); return draw(); } }),
        el("span", {}, (state.offset + 1) + "–" + Math.min(state.offset + PAGE, page.total) + " / " + page.total),
        button("下一页", { size: "sm", disabled: state.offset + PAGE >= page.total, onclick: () => { state.offset += PAGE; return draw(); } }),
      ] : []));
    } catch (error) {
      toast(error.message, "error");
    }
  }
  const search = searchBox(state.q, (event) => {
    state.q = event.target.value;
    state.offset = 0;
    clearTimeout(state.timer);
    state.timer = setTimeout(draw, 250);
  });
  draw();
  return el("div", {}, el("div", { class: "toolbar" }, search), body, pager);
}

// ---- Secrets to copy ----

// The clipboard API needs HTTPS, and the console may be reached over plain HTTP.
async function copyText(text, node) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    getSelection().selectAllChildren(node);
    return document.execCommand("copy");
  }
}

// Says what happened on the button itself: a toast would sit behind an open dialog.
function secretRow({ label, hint, secret }) {
  const text = el("code", { class: "secret-text mono" }, secret);
  let timer;
  const copy = button("复制", { size: "sm", icon: "copy", onclick: async () => {
    const copied = await copyText(secret, text);
    copy.lastChild.textContent = copied ? "已复制" : "已选中，请手动复制";
    clearTimeout(timer);
    timer = setTimeout(() => { copy.lastChild.textContent = "复制"; }, 2000);
  } });
  return el("div", { class: "secret-row" },
    el("div", { class: "secret-head" },
      el("div", { class: "secret-label" }, el("strong", {}, label), hint && el("span", { class: "secret-hint mono" }, hint)),
      copy),
    text);
}
