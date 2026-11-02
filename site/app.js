(function () {
  "use strict";
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Points people at the build for their own system.
  function detectOs() {
    var text = (navigator.userAgent + " " + (navigator.platform || "")).toLowerCase();
    if (/android|iphone|ipad/.test(text)) return null;
    if (text.indexOf("win") !== -1) return "windows";
    if (text.indexOf("mac") !== -1) return "macos";
    if (text.indexOf("linux") !== -1) return "linux";
    return null;
  }
  var os = detectOs();
  if (os) {
    var row = document.querySelector('.dl-row[data-os="' + os + '"]');
    if (row) row.classList.add("current");
    var names = { windows: "Windows", macos: "macOS", linux: "Linux" };
    var primary = document.getElementById("primary-download");
    if (primary) primary.textContent = "下载 " + names[os] + " 版";
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
