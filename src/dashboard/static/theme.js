(function () {
  try {
    var saved = localStorage.getItem("wafpulse-theme");
    if (saved === "light" || saved === "dark") { document.documentElement.setAttribute("data-theme", saved); }
  } catch (e) { /* storage can be blocked; the system theme applies */ }
})();
