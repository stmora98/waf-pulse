(function () {
  var button = document.getElementById("refresh");
  var message = document.getElementById("refresh-message");
  if (!button) { return; }

  function done(text) {
    message.textContent = text;
    button.disabled = false;
    button.classList.remove("loading");
    button.removeAttribute("aria-busy");
  }

  button.addEventListener("click", function () {
    button.disabled = true;
    button.classList.add("loading");
    button.setAttribute("aria-busy", "true");
    message.textContent = "Requesting refresh...";
    fetch("/api/refresh", { method: "POST", headers: { "X-WAF-Pulse": "1" } })
      .then(function (response) {
        return response.json().then(function (body) {
          done(body.message || body.error || "Done.");
        });
      })
      .catch(function () {
        done("The refresh request failed.");
      });
  });
})();

(function () {
  var input = document.querySelector("[data-filter-table]");
  if (!input) { return; }
  var table = document.getElementById(input.getAttribute("data-filter-table"));
  if (!table) { return; }
  input.addEventListener("input", function () {
    var needle = input.value.trim().toLowerCase();
    Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
      row.hidden = needle !== "" && row.textContent.toLowerCase().indexOf(needle) === -1;
    });
  });
})();

(function () {
  var button = document.getElementById("theme-toggle");
  if (!button) { return; }
  var order = ["auto", "light", "dark"];
  var labels = { auto: "Theme: auto", light: "Theme: light", dark: "Theme: dark" };

  function current() {
    var value = document.documentElement.getAttribute("data-theme");
    return value === "light" || value === "dark" ? value : "auto";
  }

  function show() { button.textContent = labels[current()]; }

  button.addEventListener("click", function () {
    var next = order[(order.indexOf(current()) + 1) % order.length];
    if (next === "auto") { document.documentElement.removeAttribute("data-theme"); }
    else { document.documentElement.setAttribute("data-theme", next); }
    try {
      if (next === "auto") { localStorage.removeItem("wafpulse-theme"); }
      else { localStorage.setItem("wafpulse-theme", next); }
    } catch (e) { /* storage can be blocked; the choice lasts until the page closes */ }
    show();
  });
  show();
})();

(function () {
  var root = document.documentElement;
  var buttons = [document.getElementById("nav-toggle"), document.getElementById("nav-open")];
  var narrow = window.matchMedia ? window.matchMedia("(max-width: 860px)") : { matches: false };

  function collapsed() { return root.getAttribute("data-nav") === "collapsed"; }
  function sync() { if (buttons[0]) { buttons[0].setAttribute("aria-expanded", collapsed() ? "false" : "true"); } }

  function toggle() {
    if (collapsed()) { root.removeAttribute("data-nav"); } else { root.setAttribute("data-nav", "collapsed"); }
    try {
      if (!narrow.matches) { localStorage.setItem("wafpulse-nav", collapsed() ? "collapsed" : "expanded"); }
    } catch (e) { /* storage can be blocked */ }
    sync();
  }

  buttons.forEach(function (button) { if (button) { button.addEventListener("click", toggle); } });
  // After choosing a page on a small screen the menu gets out of the way.
  var links = document.querySelectorAll(".side-link");
  Array.prototype.forEach.call(links, function (link) {
    link.addEventListener("click", function () { if (narrow.matches) { root.setAttribute("data-nav", "collapsed"); } });
  });
  sync();
})();