(function () {
  var button = document.getElementById("refresh");
  var message = document.getElementById("refresh-message");
  if (!button) { return; }

  button.addEventListener("click", function () {
    button.disabled = true;
    message.textContent = "Requesting refresh...";
    fetch("/api/refresh", { method: "POST", headers: { "X-WAF-Pulse": "1" } })
      .then(function (response) {
        return response.json().then(function (body) {
          message.textContent = body.message || body.error || "Done.";
        });
      })
      .catch(function () {
        message.textContent = "The refresh request failed.";
      })
      .finally(function () {
        button.disabled = false;
      });
  });
})();
