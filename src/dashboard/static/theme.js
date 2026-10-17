(function () {
  try {
    var saved = localStorage.getItem("wafpulse-theme");
    if (saved === "light" || saved === "dark") { document.documentElement.setAttribute("data-theme", saved); }
  } catch (e) { /* storage can be blocked; the system theme applies */ }
  try {
    var narrow = window.matchMedia && window.matchMedia("(max-width: 860px)").matches;
    var nav = localStorage.getItem("wafpulse-nav");
    // On a small screen the menu starts hidden; on a wide one it keeps the last choice.
    if (narrow || nav === "collapsed") { document.documentElement.setAttribute("data-nav", "collapsed"); }
  } catch (e) { /* the menu starts open */ }
})();
