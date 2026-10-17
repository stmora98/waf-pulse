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