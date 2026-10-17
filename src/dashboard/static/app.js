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
  var design = JSON.parse(box.getAttribute("data-design") || "null");
  var facts = JSON.parse(box.getAttribute("data-facts") || "{}");
  var selected = null;
  var KIND = { mg: "management group", sub: "subscription", root: "tenant root" };
  var MAX_DEPTH = 8;

  function element(tag, text, className) {
    var node = document.createElement(tag);
    if (text) { node.textContent = text; }
    if (className) { node.className = className; }
    return node;
  }

  function find(id, node, parent) {
    if (node.id === id) { return { node: node, parent: parent }; }
    for (var i = 0; i < node.children.length; i += 1) {
      var found = find(id, node.children[i], node);
      if (found) { return found; }
    }
    return null;
  }

  function depthOf(id) {
    var depth = 0;
    var current = find(id, design, null);
    while (current && current.parent) { depth += 1; current = find(current.parent.id, design, null); }
    return depth;
  }

  function newId() { return "n" + Math.random().toString(36).slice(2, 9); }

  function save(body, message) {
    status.textContent = message;
    return fetch("/api/landing-zone-design", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-WAF-Pulse": "1" },
      body: JSON.stringify(body)
    }).then(function (response) {
      if (response.ok) { window.location.reload(); return null; }
      return response.json().then(function (result) { throw new Error(result.error || "failed"); });
    }).catch(function (error) {
      var text = error.message === "failed" ? "The diagram could not be saved." : error.message;
      status.textContent = text;
      var shown = pop.querySelector(".lz-error");
      if (shown) { shown.textContent = text; }
    });
  }

  function persist(message) { return save({ design: design }, message); }

  function close() {
    pop.hidden = true;
    if (selected) { selected.classList.remove("selected"); selected = null; }
  }

  function button(label, handler, className) {
    var item = element("button", label, className);
    item.type = "button";
    item.addEventListener("click", handler);
    return item;
  }

  function open(target) {
    var id = target.getAttribute("data-lz-node");
    var found = find(id, design, null);
    if (!found) { return; }
    var node = found.node;
    var parent = found.parent;
    var fact = facts[id] || { status: "missing", matches: [] };
    if (selected) { selected.classList.remove("selected"); }
    selected = target;
    target.classList.add("selected");
    var isRoot = node.kind === "root";

    pop.textContent = "";
    pop.appendChild(element("h4", node.label));
    pop.appendChild(element("p", isRoot ? "The top of every tenant." :
      (fact.status === "present" ? "Found: " + fact.matches.join(", ") : "Not found in your tenant yet."), "muted"));

    var name = element("input", "", "lz-input");
    name.type = "text";
    name.value = node.label;
    name.maxLength = 60;
    name.setAttribute("aria-label", "Name of the box");
    pop.appendChild(element("label", "Name"));
    pop.lastChild.appendChild(name);

    var kind = element("select");
    kind.setAttribute("aria-label", "Type of the box");
    [["mg", "Management group"], ["sub", "Subscription"]].forEach(function (option) {
      var item = element("option", option[1]);
      item.value = option[0];
      kind.appendChild(item);
    });
    kind.value = node.kind === "sub" ? "sub" : "mg";
    var link = element("input", "", "lz-input");
    link.type = "text";
    link.maxLength = 100;
    link.autocomplete = "off";
    link.value = node.link || "";
    link.setAttribute("aria-label", "The real management group or subscription");

    function syncLink() {
      link.setAttribute("list", kind.value === "sub" ? "lz-subscriptions" : "lz-groups");
      link.placeholder = "Pick or type a " + (kind.value === "sub" ? "subscription" : "management group");
    }
    syncLink();
    kind.addEventListener("change", syncLink);

    if (!isRoot) {
      var kindLabel = element("label", "Type");
      kindLabel.appendChild(kind);
      pop.appendChild(kindLabel);
      var linkLabel = element("label", "Linked to (optional, one of your own, of the same type)");
      linkLabel.appendChild(link);
      pop.appendChild(linkLabel);
    }
    pop.appendChild(element("p", "", "lz-error"));

    var main = element("div", "", "lz-row");
    if (!isRoot) {
      main.appendChild(button("Apply", function () {
        var chosen = kind.value;
        var text = name.value.trim();
        if (!text) { pop.querySelector(".lz-error").textContent = "The box needs a name."; return; }
        if (chosen === "sub" && node.children.length) {
          pop.querySelector(".lz-error").textContent = "A subscription cannot have boxes below it. Delete or move them first.";
          return;
        }
        var typed = link.value.trim();
        var changedKind = chosen !== node.kind;
        // A link of the old type makes no sense for the new one: it is dropped unless a new one was typed.
        node.link = changedKind && typed === (node.link || "") ? "" : typed;
        if (changedKind && chosen === "sub") { node.role = ""; }
        node.kind = chosen;
        node.label = text;
        persist("Saving...");
      }));
    } else {
      main.appendChild(button("Rename", function () {
        var text = name.value.trim();
        if (!text) { return; }
        node.label = text;
        persist("Saving...");
      }));
    }
    pop.appendChild(main);

    if (node.kind !== "sub") {
      var add = element("div", "", "lz-row tight");
      var tooDeep = depthOf(id) >= MAX_DEPTH;
      var addGroup = button("+ Management group below", function () {
        node.children.push({ id: newId(), label: "New management group", kind: "mg", role: "", link: "", children: [] });
        persist("Adding...");
      }, "icon-button");
      var addSub = button("+ Subscription below", function () {
        node.children.push({ id: newId(), label: "Subscription", kind: "sub", role: "", link: "", children: [] });
        persist("Adding...");
      }, "icon-button");
      addGroup.disabled = tooDeep;
      addSub.disabled = tooDeep;
      add.appendChild(addGroup);
      add.appendChild(addSub);
      pop.appendChild(add);
    }

    if (parent) {
      var move = element("div", "", "lz-row tight");
      var index = parent.children.indexOf(node);
      var left = button("Move left", function () {
        parent.children.splice(index, 1);
        parent.children.splice(index - 1, 0, node);
        persist("Moving...");
      }, "icon-button");
      var right = button("Move right", function () {
        parent.children.splice(index, 1);
        parent.children.splice(index + 1, 0, node);
        persist("Moving...");
      }, "icon-button");
      left.disabled = index === 0;
      right.disabled = index === parent.children.length - 1;
      var remove = button(node.children.length ? "Delete with what is below" : "Delete", function () {
        parent.children.splice(index, 1);
        persist("Deleting...");
      }, "icon-button");
      move.appendChild(left);
      move.appendChild(right);
      move.appendChild(remove);
      pop.appendChild(move);
    }
    var last = element("div", "", "lz-row tight");
    last.appendChild(button("Close", close, "icon-button"));
    pop.appendChild(last);

    pop.hidden = false;
    var wrap = box.getBoundingClientRect();
    var rect = target.getBoundingClientRect();
    pop.style.left = Math.max(4, Math.min(rect.left - wrap.left, wrap.width - pop.offsetWidth - 4)) + "px";
    pop.style.top = (rect.bottom - wrap.top + 8) + "px";
    name.focus();
  }

  Array.prototype.forEach.call(box.querySelectorAll("[data-lz-node]"), function (target) {
    target.addEventListener("click", function (event) { event.stopPropagation(); open(target); });
    target.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); event.stopPropagation(); open(target); }
    });
  });
  pop.addEventListener("click", function (event) { event.stopPropagation(); });
  document.addEventListener("click", close);
  document.addEventListener("keydown", function (event) { if (event.key === "Escape") { close(); } });
  var reset = document.getElementById("lz-reset");
  if (reset) { reset.addEventListener("click", function () { save({ reset: true }, "Going back to the reference..."); }); }
})();
