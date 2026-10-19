/* Places a popover next to its anchor and keeps all of it on the screen: it slides up or opens above the anchor when
   there is no room below, and it is never taller than the window (its list scrolls and its buttons stay in view). */
function fitPopover(pop, container, anchor) {
  pop.hidden = false;
  pop.style.maxHeight = Math.max(window.innerHeight - 16, 160) + "px";
  var wrap = container.getBoundingClientRect();
  var rect = anchor.getBoundingClientRect();
  var left = Math.max(0, Math.min(rect.left - wrap.left, wrap.width - pop.offsetWidth));
  var top = rect.bottom - wrap.top + 6;
  pop.style.left = left + "px";
  pop.style.top = top + "px";
  var overflow = pop.getBoundingClientRect().bottom - (window.innerHeight - 8);
  if (overflow > 0) {
    var roomAbove = rect.top - 8;
    top = roomAbove >= pop.offsetHeight + 6 ? rect.top - wrap.top - pop.offsetHeight - 6 : top - overflow;
    pop.style.top = top + "px";
  }
  var shortBy = 8 - pop.getBoundingClientRect().top;
  if (shortBy > 0) { pop.style.top = (parseFloat(pop.style.top) + shortBy) + "px"; }
}

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

    fitPopover(pop, box, target);
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

(function () {
  var bar = document.getElementById("filterbar");
  if (!bar) { return; }
  var pop = document.getElementById("filter-pop");
  var facets = JSON.parse(bar.getAttribute("data-facets") || "{}");
  var fields = facets.fields || {};
  var active = facets.active || {};
  var MENU = facets.menu || [
    { field: "subscription", label: "Subscription", kind: "facet" },
    { field: "group", label: "Resource group", kind: "facet" },
    { field: "type", label: "Resource type", kind: "facet" },
    { field: "location", label: "Location", kind: "facet" },
    { field: "findings", label: "Findings", kind: "radio", choices: [["with", "With findings"], ["without", "Without findings"]] },
    { field: "name", label: "Name", kind: "text" }
  ];
  function entryOf(field) {
    for (var i = 0; i < MENU.length; i++) { if (MENU[i].field === field) { return MENU[i]; } }
    return { field: field, label: field, kind: "facet" };
  }

  function element(tag, text, className) {
    var node = document.createElement(tag);
    if (text) { node.textContent = text; }
    if (className) { node.className = className; }
    return node;
  }

  function close() { pop.hidden = true; }

  function place(anchor) { fitPopover(pop, bar, anchor); }

  function go(field, op, values) {
    var params = new URLSearchParams(window.location.search);
    params.delete(field);
    params.delete(field + "_op");
    params.delete("page");
    values.forEach(function (value) { params.append(field, value); });
    if (values.length && op === "ne") { params.set(field + "_op", "ne"); }
    window.location.search = params.toString();
  }

  function editFacet(field, anchor) {
    var spec = fields[field];
    var current = active[field] || { op: "eq", values: [] };
    var chosen = {};
    current.values.forEach(function (value) { chosen[String(value).toLowerCase()] = true; });
    pop.textContent = "";
    pop.appendChild(element("h4", spec.label));
    var op = element("select");
    [["eq", "equals"], ["ne", "does not equal"]].forEach(function (pair) {
      var option = element("option", pair[1]);
      option.value = pair[0];
      op.appendChild(option);
    });
    op.value = current.op === "ne" ? "ne" : "eq";
    op.setAttribute("aria-label", "Operator");
    pop.appendChild(op);
    var search = element("input", "", "lz-input");
    search.type = "search";
    search.placeholder = "Search " + spec.label.toLowerCase();
    pop.appendChild(search);
    var box = element("div", "", "fopts");
    var rows = [];
    spec.options.forEach(function (entry) {
      var label = element("label");
      var check = element("input");
      check.type = "checkbox";
      check.value = entry[0];
      check.checked = !!chosen[String(entry[0]).toLowerCase()];
      label.appendChild(check);
      label.appendChild(element("span", entry[1]));
      label.appendChild(element("span", String(entry[2]), "count"));
      box.appendChild(label);
      rows.push({ label: label, text: String(entry[1]).toLowerCase(), check: check });
    });
    if (!rows.length) { box.appendChild(element("p", "Nothing to choose from.", "muted")); }
    search.addEventListener("input", function () {
      var needle = search.value.trim().toLowerCase();
      rows.forEach(function (row) { row.label.hidden = needle !== "" && row.text.indexOf(needle) === -1; });
    });
    pop.appendChild(box);
    var actions = element("div", "", "lz-row");
    var apply = element("button", "Apply");
    apply.type = "button";
    apply.addEventListener("click", function () {
      var values = rows.filter(function (row) { return row.check.checked; }).map(function (row) { return row.check.value; });
      go(field, op.value, values);
    });
    var cancel = element("button", "Cancel", "icon-button");
    cancel.type = "button";
    cancel.addEventListener("click", close);
    actions.appendChild(apply);
    actions.appendChild(cancel);
    pop.appendChild(actions);
    place(anchor);
    search.focus();
  }

  function editRadio(entry, anchor) {
    var field = entry.field;
    var current = (active[field] && active[field].values[0]) || "";
    pop.textContent = "";
    pop.appendChild(element("h4", entry.label));
    var box = element("div", "", "fopts");
    (entry.choices || []).forEach(function (pair) {
      var label = element("label");
      var radio = element("input");
      radio.type = "radio";
      radio.name = field;
      radio.value = pair[0];
      radio.checked = current === pair[0];
      label.appendChild(radio);
      label.appendChild(element("span", pair[1]));
      box.appendChild(label);
    });
    pop.appendChild(box);
    var actions = element("div", "", "lz-row");
    var apply = element("button", "Apply");
    apply.type = "button";
    apply.addEventListener("click", function () {
      var picked = box.querySelector("input:checked");
      go(field, "eq", picked ? [picked.value] : []);
    });
    var cancel = element("button", "Cancel", "icon-button");
    cancel.type = "button";
    cancel.addEventListener("click", close);
    actions.appendChild(apply);
    actions.appendChild(cancel);
    pop.appendChild(actions);
    place(anchor);
  }

  function editText(entry, anchor) {
    var field = entry.field;
    var current = (active[field] && active[field].values[0]) || "";
    pop.textContent = "";
    pop.appendChild(element("h4", entry.label + " contains"));
    var input = element("input", "", "lz-input");
    input.type = "text";
    input.maxLength = 150;
    input.value = current;
    input.placeholder = "Part of a resource name";
    pop.appendChild(input);
    var actions = element("div", "", "lz-row");
    var apply = element("button", "Apply");
    apply.type = "button";
    function submit() { go(field, "contains", input.value.trim() ? [input.value.trim()] : []); }
    apply.addEventListener("click", submit);
    input.addEventListener("keydown", function (event) { if (event.key === "Enter") { submit(); } });
    var cancel = element("button", "Cancel", "icon-button");
    cancel.type = "button";
    cancel.addEventListener("click", close);
    actions.appendChild(apply);
    actions.appendChild(cancel);
    pop.appendChild(actions);
    place(anchor);
    input.focus();
  }

  function edit(field, anchor) {
    var entry = entryOf(field);
    if (entry.kind === "radio") { editRadio(entry, anchor); }
    else if (entry.kind === "text") { editText(entry, anchor); }
    else { editFacet(field, anchor); }
  }

  var add = document.getElementById("filter-add");
  add.addEventListener("click", function (event) {
    event.stopPropagation();
    pop.textContent = "";
    pop.appendChild(element("h4", "Add filter"));
    MENU.forEach(function (entry) {
      var field = entry.field;
      var item = element("button", entry.label, "fmenu-item");
      item.type = "button";
      if (active[field]) { item.disabled = true; item.title = "Already added: change it from its pill"; }
      item.addEventListener("click", function (click) { click.stopPropagation(); edit(field, add); });
      pop.appendChild(item);
    });
    place(add);
  });
  Array.prototype.forEach.call(bar.querySelectorAll("[data-filter-edit]"), function (button) {
    button.addEventListener("click", function (event) {
      event.stopPropagation();
      edit(button.getAttribute("data-filter-edit"), button);
    });
  });
  pop.addEventListener("click", function (event) { event.stopPropagation(); });
  document.addEventListener("click", close);
  document.addEventListener("keydown", function (event) { if (event.key === "Escape") { close(); } });
})();

(function () {
  var form = document.getElementById("thresholds-form");
  if (!form) { return; }
  var status = document.getElementById("thresholds-status");
  var reset = document.getElementById("thresholds-reset");

  function send(body) {
    status.textContent = "Saving...";
    return fetch("/api/rightsizing-thresholds", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-WAF-Pulse": "1" },
      body: JSON.stringify(body)
    }).then(function (response) {
      if (response.ok) { window.location.reload(); return null; }
      return response.json().then(function (result) { throw new Error(result.error || "failed"); });
    }).catch(function (error) {
      status.textContent = error.message === "failed" ? "The thresholds could not be saved." : error.message;
    });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var thresholds = {};
    Array.prototype.forEach.call(form.querySelectorAll("input[name]"), function (input) {
      var parts = input.name.split(".");
      thresholds[parts[0]] = thresholds[parts[0]] || {};
      thresholds[parts[0]][parts[1]] = Number(input.value);
    });
    send({ thresholds: thresholds });
  });
  reset.addEventListener("click", function () { send({ reset: true }); });
})();

(function () {
  var table = document.getElementById("rs");
  var panel = document.getElementById("selection");
  if (!table || !panel) { return; }
  var all = document.getElementById("pick-all");
  var boxes = Array.prototype.slice.call(table.querySelectorAll(".pick-row"));

  function number(value) { var n = parseFloat(value); return isFinite(n) ? n : 0; }

  function chosen() {
    return boxes.filter(function (box) { return box.checked; }).map(function (box) { return box.closest("tr"); });
  }

  function refresh() {
    var rows = chosen();
    var saving = 0, cost = 0;
    rows.forEach(function (row) { saving += number(row.getAttribute("data-saving")); cost += number(row.getAttribute("data-cost")); });
    panel.hidden = rows.length === 0;
    document.getElementById("sel-count").textContent = String(rows.length);
    document.getElementById("sel-saving").textContent = Math.round(saving).toLocaleString();
    document.getElementById("sel-cost").textContent = Math.round(cost).toLocaleString();
    all.checked = rows.length > 0 && rows.length === boxes.length;
    all.indeterminate = rows.length > 0 && rows.length < boxes.length;
  }

  function cell(value) {
    var text = String(value);
    if (/^[=+\-@\t\r]/.test(text)) { text = "'" + text; }
    return '"' + text.replace(/"/g, '""') + '"';
  }

  boxes.forEach(function (box) { box.addEventListener("change", refresh); });
  all.addEventListener("change", function () { boxes.forEach(function (box) { box.checked = all.checked; }); refresh(); });
  document.getElementById("sel-clear").addEventListener("click", function () { boxes.forEach(function (box) { box.checked = false; }); refresh(); });
  document.getElementById("sel-csv").addEventListener("click", function () {
    var lines = [["Name", "Size", "Advisor", "Monthly savings", "Cost 30 days", "Resource ID"].map(cell).join(",")];
    chosen().forEach(function (row) {
      lines.push([row.getAttribute("data-name"), row.getAttribute("data-size"), row.getAttribute("data-advice"), row.getAttribute("data-saving"),
                  row.getAttribute("data-cost"), row.getAttribute("data-id")].map(cell).join(","));
    });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv" }));
    link.download = "right-sizing-selection.csv";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  });
})();

(function () {
  var buttons = document.querySelectorAll(".suppress-btn");
  var restore = document.querySelectorAll("[data-restore]");
  if (!buttons.length && !restore.length) { return; }
  var DURATIONS = [[0, "Forever"], [30, "30 days"], [90, "90 days"], [180, "180 days"], [365, "1 year"]];
  var pop = document.createElement("div");
  pop.className = "sup-pop";
  pop.hidden = true;
  pop.setAttribute("role", "dialog");
  pop.setAttribute("aria-label", "Suppress");
  document.body.appendChild(pop);

  function element(tag, text, className) {
    var node = document.createElement(tag);
    if (text) { node.textContent = text; }
    if (className) { node.className = className; }
    return node;
  }

  function send(body, onError) {
    return fetch("/api/suppressions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-WAF-Pulse": "1" },
      body: JSON.stringify(body)
    }).then(function (response) {
      if (response.ok) { window.location.reload(); return null; }
      return response.json().then(function (result) { throw new Error(result.error || "failed"); });
    }).catch(function (error) {
      onError(error.message === "failed" ? "It could not be saved." : error.message);
    });
  }

  function place(anchor) {
    pop.hidden = false;
    var rect = anchor.getBoundingClientRect();
    var left = Math.max(8, Math.min(rect.left, window.innerWidth - pop.offsetWidth - 8));
    var top = rect.bottom + 6;
    if (top + pop.offsetHeight > window.innerHeight - 8) { top = Math.max(8, rect.top - pop.offsetHeight - 6); }
    pop.style.left = left + "px";
    pop.style.top = top + "px";
  }

  function open(button) {
    var resource = button.getAttribute("data-resource");
    pop.textContent = "";
    pop.appendChild(element("h4", resource ? "Suppress for this resource" : "Suppress for every resource"));
    pop.appendChild(element("p", button.getAttribute("data-title") || "", "muted"));
    var reason = element("input", "", "lz-input");
    reason.type = "text";
    reason.maxLength = 200;
    reason.placeholder = "Why (optional)";
    reason.setAttribute("aria-label", "Reason");
    pop.appendChild(reason);
    var days = element("select");
    days.setAttribute("aria-label", "For how long");
    DURATIONS.forEach(function (pair) {
      var option = element("option", pair[1]);
      option.value = String(pair[0]);
      days.appendChild(option);
    });
    pop.appendChild(days);
    var error = element("p", "", "lz-error");
    var actions = element("div", "", "lz-row");
    var apply = element("button", "Suppress");
    apply.type = "button";
    apply.addEventListener("click", function () {
      apply.disabled = true;
      send({ add: { ruleId: button.getAttribute("data-rule"), resourceId: resource || "", days: Number(days.value),
                    reason: reason.value.trim(), ruleTitle: button.getAttribute("data-title") || "",
                    resourceName: button.getAttribute("data-name") || "" } },
           function (text) { error.textContent = text; apply.disabled = false; });
    });
    var cancel = element("button", "Cancel", "icon-button");
    cancel.type = "button";
    cancel.addEventListener("click", function () { pop.hidden = true; });
    actions.appendChild(apply);
    actions.appendChild(cancel);
    pop.appendChild(error);
    pop.appendChild(actions);
    place(button);
    reason.focus();
  }

  Array.prototype.forEach.call(buttons, function (button) {
    button.addEventListener("click", function (event) { event.stopPropagation(); open(button); });
  });
  Array.prototype.forEach.call(restore, function (button) {
    button.addEventListener("click", function () {
      button.disabled = true;
      send({ remove: button.getAttribute("data-restore") }, function (text) {
        var status = document.getElementById("suppress-status");
        if (status) { status.textContent = text; }
        button.disabled = false;
      });
    });
  });
  pop.addEventListener("click", function (event) { event.stopPropagation(); });
  document.addEventListener("click", function () { pop.hidden = true; });
  document.addEventListener("keydown", function (event) { if (event.key === "Escape") { pop.hidden = true; } });
})();

(function () {
  var bar = document.getElementById("scope-bar");
  if (!bar) { return; }
  var pop = document.getElementById("scope-pop");
  var addButton = document.getElementById("scope-add");
  var state = null; // { options, filters }

  function element(tag, text, className) {
    var node = document.createElement(tag);
    if (text) { node.textContent = text; }
    if (className) { node.className = className; }
    return node;
  }

  function close() { pop.hidden = true; }
  function place(anchor) { fitPopover(pop, bar, anchor); }

  function save(filters, error) {
    return fetch("/api/scope", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-WAF-Pulse": "1" },
      body: JSON.stringify(filters.length ? { filters: filters } : { clear: true })
    }).then(function (response) {
      if (response.ok) { window.location.reload(); return null; }
      return response.json().then(function (result) { throw new Error(result.error || "failed"); });
    }).catch(function (problem) {
      var text = problem.message === "failed" ? "The filters could not be saved." : problem.message;
      if (error) { error.textContent = text; }
    });
  }

  function load() {
    if (state) { return Promise.resolve(state); }
    return fetch("/api/scope-options").then(function (response) {
      if (!response.ok) { throw new Error("failed"); }
      return response.json();
    }).then(function (result) { state = { options: result.options, filters: result.current || [] }; return state; });
  }

  var FIELD_ORDER = ["sub", "mg", "rg", "type", "loc", "tag"];

  function menu() {
    load().then(function (current) {
      pop.textContent = "";
      pop.appendChild(element("h4", "Add filter"));
      FIELD_ORDER.forEach(function (field) {
        var spec = current.options.fields[field];
        var item = element("button", spec.label, "fmenu-item");
        item.type = "button";
        item.addEventListener("click", function (event) { event.stopPropagation(); edit({ f: field, op: "eq", v: [] }, -1, addButton); });
        pop.appendChild(item);
      });
      place(addButton);
    }).catch(function () { pop.textContent = "The filter options could not be loaded."; place(addButton); });
  }

  function operator(entry) {
    var op = element("select");
    [["eq", "equals"], ["ne", "does not equal"]].forEach(function (pair) {
      var option = element("option", pair[1]);
      option.value = pair[0];
      op.appendChild(option);
    });
    op.value = entry.op === "ne" ? "ne" : "eq";
    op.setAttribute("aria-label", "Operator");
    return op;
  }

  function actions(onApply, error) {
    var row = element("div", "", "lz-row");
    var apply = element("button", "Apply");
    apply.type = "button";
    apply.addEventListener("click", function () { apply.disabled = true; onApply().then(function () { apply.disabled = false; }); });
    var cancel = element("button", "Cancel", "icon-button");
    cancel.type = "button";
    cancel.addEventListener("click", close);
    row.appendChild(apply);
    row.appendChild(cancel);
    return row;
  }

  function submit(entry, index, error) {
    var filters = state.filters.slice();
    if (index >= 0) { filters[index] = entry; } else { filters.push(entry); }
    return save(filters, error);
  }

  function edit(entry, index, anchor) {
    load().then(function () {
      var spec = state.options.fields[entry.f];
      pop.textContent = "";
      var title = entry.f === "tag" ? "Tag" : spec.label;
      pop.appendChild(element("h4", title));
      var op = operator(entry);
      pop.appendChild(op);
      var error = element("p", "", "lz-error");
      var names = {};
      var collect;

      function facetList(container, options, chosen) {
        var search = element("input", "", "lz-input");
        search.type = "search";
        search.placeholder = "Search";
        container.appendChild(search);
        var box = element("div", "", "fopts");
        var rows = [];
        var picked = {};
        chosen.forEach(function (value) { picked[String(value).toLowerCase()] = true; });
        options.forEach(function (option) {
          var label = element("label");
          var check = element("input");
          check.type = "checkbox";
          check.value = option.value;
          check.checked = !!picked[String(option.value).toLowerCase()];
          label.appendChild(check);
          label.appendChild(element("span", option.text || option.value));
          if (option.count !== undefined) { label.appendChild(element("span", String(option.count), "count")); }
          box.appendChild(label);
          rows.push({ label: label, text: String(option.text || option.value).toLowerCase(), check: check, option: option });
        });
        if (!rows.length) { box.appendChild(element("p", "Nothing to choose from.", "muted")); }
        search.addEventListener("input", function () {
          var needle = search.value.trim().toLowerCase();
          rows.forEach(function (row) { row.label.hidden = needle !== "" && row.text.indexOf(needle) === -1; });
        });
        container.appendChild(box);
        return function () {
          var values = [], text = {};
          rows.forEach(function (row) {
            if (row.check.checked) { values.push(row.check.value); if (row.option.text && row.option.text !== row.option.value) { text[row.option.value.toLowerCase()] = row.option.text; } }
          });
          return { values: values, names: text };
        };
      }

      if (entry.f === "tag") {
        var keySelect = element("select");
        keySelect.setAttribute("aria-label", "Tag name");
        var keys = (spec.keys || []);
        if (!state.options.tagsAvailable || !keys.length) {
          pop.appendChild(element("p", state.options.tagsAvailable ? "No tags found." : "Tags appear after the next refresh.", "muted"));
          pop.appendChild(actions(function () { close(); return Promise.resolve(); }, error));
          place(anchor);
          return;
        }
        keys.forEach(function (key) {
          var option = element("option", key.key + " (" + key.count + ")");
          option.value = key.key;
          keySelect.appendChild(option);
        });
        if (entry.k) { keySelect.value = entry.k; }
        pop.insertBefore(keySelect, op);
        var holder = element("div");
        pop.appendChild(holder);
        var render = function () {
          holder.textContent = "";
          var key = keys.filter(function (k) { return k.key === keySelect.value; })[0];
          var saved = (entry.k === keySelect.value) ? entry.v : [];
          collect = facetList(holder, (key ? key.values : []).map(function (v) { return { value: v.value, text: v.value, count: v.count }; }), saved);
        };
        keySelect.addEventListener("change", render);
        render();
      } else {
        collect = facetList(pop, spec.options, entry.v);
      }
      pop.appendChild(error);
      pop.appendChild(actions(function () {
        var picked = collect();
        if (entry.f !== "tag" && !picked.values.length) { error.textContent = "Choose at least one value."; return Promise.resolve(); }
        var next = { f: entry.f, op: op.value, v: picked.values };
        if (entry.f === "tag") { next.k = keySelect.value; }
        if (Object.keys(picked.names).length) { next.n = picked.names; }
        return submit(next, index, error);
      }, error));
      place(anchor);
    }).catch(function () { pop.textContent = "The filter options could not be loaded."; place(anchor); });
  }

  addButton.addEventListener("click", function (event) { event.stopPropagation(); if (!pop.hidden) { close(); } else { menu(); } });
  Array.prototype.forEach.call(bar.querySelectorAll("[data-scope-edit]"), function (button) {
    button.addEventListener("click", function (event) {
      event.stopPropagation();
      var index = Number(button.getAttribute("data-scope-edit"));
      load().then(function () { edit(state.filters[index], index, button); });
    });
  });
  Array.prototype.forEach.call(bar.querySelectorAll("[data-scope-remove]"), function (button) {
    button.addEventListener("click", function () {
      var index = Number(button.getAttribute("data-scope-remove"));
      load().then(function () { var filters = state.filters.slice(); filters.splice(index, 1); return save(filters); });
    });
  });
  var clear = document.getElementById("scope-clear");
  if (clear) { clear.addEventListener("click", function () { save([]); }); }
  pop.addEventListener("click", function (event) { event.stopPropagation(); });
  document.addEventListener("click", close);
  document.addEventListener("keydown", function (event) { if (event.key === "Escape") { close(); } });
})();
