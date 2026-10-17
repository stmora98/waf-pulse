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

(function () {
  var box = document.getElementById("lz-map");
  if (!box) { return; }
  var pop = document.getElementById("lz-pop");
  var status = document.getElementById("lz-status");
  var rows = JSON.parse(box.getAttribute("data-rows") || "[]");
  var mapping = JSON.parse(box.getAttribute("data-mapping") || "{}");
  var hidden = (box.getAttribute("data-hidden") || "").split(",").filter(Boolean);
  var selected = null;

  function save(message) {
    status.textContent = message;
    fetch("/api/landing-zone-map", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-WAF-Pulse": "1" },
      body: JSON.stringify({ mapping: mapping, hidden: hidden })
    }).then(function (response) {
      if (!response.ok) { throw new Error("failed"); }
      window.location.reload();
    }).catch(function () {
      status.textContent = "The changes could not be saved.";
    });
  }

  function element(tag, text, className) {
    var node = document.createElement(tag);
    if (text) { node.textContent = text; }
    if (className) { node.className = className; }
    return node;
  }

  function close() {
    pop.hidden = true;
    if (selected) { selected.classList.remove("selected"); selected = null; }
  }

  function open(group) {
    var role = group.getAttribute("data-lz-box");
    var row = rows.filter(function (item) { return item.role === role; })[0];
    if (!row) { return; }
    if (selected) { selected.classList.remove("selected"); }
    selected = group;
    group.classList.add("selected");
    var names = (mapping[role] || []).slice();

    pop.textContent = "";
    pop.appendChild(element("h4", row.label));
    pop.appendChild(element("p", row.found ? "Found: " + row.matches.join(", ") : "Not found in your tenant yet.", "muted"));
    var list = element("div", "", "lz-names");
    names.forEach(function (name) {
      var chip = element("button", name, "chip-button");
      chip.type = "button";
      chip.title = "Stop using this name";
      chip.addEventListener("click", function () {
        mapping[role] = names.filter(function (item) { return item !== name; });
        if (!mapping[role].length) { delete mapping[role]; }
        save("Saving...");
      });
      list.appendChild(chip);
    });
    pop.appendChild(list);
    (row.unmatched || []).forEach(function (name) {
      pop.appendChild(element("p", "No management group or subscription is called " + name + ".", "muted"));
    });
    var input = element("input", "", "lz-input");
    input.type = "text";
    input.setAttribute("list", "lz-options");
    input.setAttribute("autocomplete", "off");
    input.maxLength = 100;
    input.placeholder = "Pick or type a management group or subscription";
    input.setAttribute("aria-label", "Management group or subscription for " + row.label);
    pop.appendChild(input);

    var actions = element("div", "", "lz-row");
    var add = element("button", "Map it");
    add.type = "button";
    function commit() {
      var value = input.value.trim();
      if (!value) { input.focus(); return; }
      if (names.indexOf(value) === -1) { names.push(value); }
      mapping[role] = names;
      save("Saving...");
    }
    add.addEventListener("click", commit);
    input.addEventListener("keydown", function (event) { if (event.key === "Enter") { commit(); } });
    var remove = element("button", "Remove this box", "icon-button");
    remove.type = "button";
    remove.addEventListener("click", function () {
      if (hidden.indexOf(role) === -1) { hidden.push(role); }
      save("Removing...");
    });
    var cancel = element("button", "Close", "icon-button");
    cancel.type = "button";
    cancel.addEventListener("click", close);
    [add, remove, cancel].forEach(function (button) { actions.appendChild(button); });
    pop.appendChild(actions);

    pop.hidden = false;
    var wrap = box.getBoundingClientRect();
    var rect = group.getBoundingClientRect();
    var left = Math.max(4, Math.min(rect.left - wrap.left, wrap.width - pop.offsetWidth - 4));
    pop.style.left = left + "px";
    pop.style.top = (rect.bottom - wrap.top + 8) + "px";
    input.focus();
  }

  Array.prototype.forEach.call(box.querySelectorAll("[data-lz-box]"), function (group) {
    group.addEventListener("click", function (event) { event.stopPropagation(); open(group); });
    group.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(group); }
    });
  });
  pop.addEventListener("click", function (event) { event.stopPropagation(); });
  document.addEventListener("click", close);
  document.addEventListener("keydown", function (event) { if (event.key === "Escape") { close(); } });

  document.getElementById("lz-reset").addEventListener("click", function () {
    mapping = {};
    hidden = [];
    save("Resetting...");
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-lz-restore]"), function (button) {
    button.addEventListener("click", function () {
      var role = button.getAttribute("data-lz-restore");
      hidden = hidden.filter(function (item) { return item !== role; });
      save("Putting it back...");
    });
  });
})();
