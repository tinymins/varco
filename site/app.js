(function () {
  "use strict";
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Download buttons fetch the build for this system. Anything unrecognised, such
  // as a phone, keeps the link to the full list: there is no build to offer it.
  var RELEASES = "https://github.com/tinymins/varco/releases/latest/download/";
  var BUILDS = {
    windows: {
      name: "Windows", row: "windows",
      x64: { file: "varco-windows-x64.exe", label: "x64" },
      arm64: { file: "varco-windows-arm64.exe", label: "ARM64" }
    },
    macos: {
      name: "macOS", row: "macos",
      x64: { file: "varco-macos-x64.zip", label: "Intel" },
      arm64: { file: "varco-macos-arm64.zip", label: "Apple 芯片" }
    },
    linux: {
      name: "Linux", row: "linux",
      x64: { file: "varco-linux-gui-x64", label: "x64" },
      arm64: { file: "varco-linux-gui-arm64", label: "ARM64" }
    }
  };

  function detectOs() {
    var text = (navigator.userAgent + " " + (navigator.platform || "")).toLowerCase();
    if (/android|iphone|ipad|ipod/.test(text)) return null;
    // iPadOS asks for desktop sites and calls itself a Mac; only touch gives it away.
    if (text.indexOf("mac") !== -1 && navigator.maxTouchPoints > 1) return null;
    if (text.indexOf("windows") !== -1 || text.indexOf("win32") !== -1) return "windows";
    if (text.indexOf("mac") !== -1) return "macos";
    if (text.indexOf("linux") !== -1) return "linux";
    return null;
  }

  // Browsers on Macs always claim Intel, and most Macs in use are not.
  function guessArch(os) {
    var text = (navigator.userAgent + " " + (navigator.platform || "")).toLowerCase();
    if (/aarch64|arm64/.test(text)) return "arm64";
    if (os === "macos") return "arm64";
    return "x64";
  }

  function applyBuild(os, arch) {
    var build = BUILDS[os];
    var target = build[arch];
    var links = document.querySelectorAll("[data-direct-download]");
    Array.prototype.forEach.call(links, function (link) {
      link.href = RELEASES + target.file;
      if (!link.hasAttribute("data-short")) {
        link.textContent = "下载 " + build.name + " 版（" + target.label + "）";
      }
    });
  }

  var os = detectOs();
  if (os) {
    var row = document.querySelector('.dl-row[data-os="' + BUILDS[os].row + '"]');
    if (row) row.classList.add("current");
    applyBuild(os, guessArch(os));
    // Chromium hides the real architecture from the user agent but will tell if asked.
    var hints = navigator.userAgentData;
    if (hints && hints.getHighEntropyValues) {
      hints.getHighEntropyValues(["architecture"]).then(function (values) {
        if (values.architecture === "arm") applyBuild(os, "arm64");
        else if (values.architecture === "x86") applyBuild(os, "x64");
      }).catch(function () {});
    }
  }

  // The hero window plays the same steps a person goes through.
  var SAMPLE = "varco1.q7Hk2mXzP0vLtR9dYwN4sBfE8uGc";
  var demo = document.getElementById("demo");
  if (!demo) return;
  var panes = {
    entry: demo.querySelector('[data-pane="entry"]'),
    joined: demo.querySelector('[data-pane="joined"]')
  };
  var codeEl = document.getElementById("demo-code");
  var confirmEl = document.getElementById("demo-confirm");
  var upEl = document.getElementById("demo-up");
  var downEl = document.getElementById("demo-down");
  var rttEl = document.getElementById("demo-rtt");

  function show(name) {
    panes.entry.hidden = name !== "entry";
    panes.joined.hidden = name !== "joined";
  }
  function formatKb(kb) {
    return kb < 1024 ? kb.toFixed(0) + " KB" : (kb / 1024).toFixed(1) + " MB";
  }
  function setTraffic(up, down) {
    upEl.textContent = formatKb(up);
    downEl.textContent = formatKb(down);
  }

  if (reduced) {
    setTraffic(1229, 8602);
    show("joined");
    return;
  }

  var timers = [];
  var ticker = null;
  function later(ms, fn) { timers.push(setTimeout(fn, ms)); }
  function stop() {
    timers.forEach(clearTimeout);
    timers = [];
    if (ticker) clearInterval(ticker);
    ticker = null;
  }
  function play() {
    stop();
    show("entry");
    codeEl.textContent = "";
    confirmEl.textContent = "确认";
    confirmEl.classList.remove("busy", "press");
    // Pasted, not typed: that is what actually happens.
    later(1300, function () { codeEl.textContent = SAMPLE; });
    later(2300, function () { confirmEl.classList.add("press"); });
    later(2450, function () {
      confirmEl.classList.remove("press");
      confirmEl.classList.add("busy");
      confirmEl.textContent = "连接中…";
    });
    later(3500, function () {
      var up = 0, down = 0;
      setTraffic(up, down);
      show("joined");
      ticker = setInterval(function () {
        up += 2 + Math.random() * 6;
        down += 6 + Math.random() * 24;
        setTraffic(up, down);
        rttEl.textContent = 34 + Math.floor(Math.random() * 9) + " ms";
      }, 700);
    });
    later(14000, play);
  }

  // Nothing runs while the window is off screen.
  if ("IntersectionObserver" in window) {
    var playing = false;
    new IntersectionObserver(function (entries) {
      var visible = entries[0].isIntersecting;
      if (visible && !playing) { playing = true; play(); }
      else if (!visible && playing) { playing = false; stop(); }
    }).observe(demo);
  } else {
    play();
  }

  var svg = document.getElementById("relay-svg");
  if (svg && svg.pauseAnimations && "IntersectionObserver" in window) {
    new IntersectionObserver(function (entries) {
      if (entries[0].isIntersecting) svg.unpauseAnimations();
      else svg.pauseAnimations();
    }).observe(svg);
  }
})();
