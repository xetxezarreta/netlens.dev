/* Learning-path progress: local checklist only. */
(function () {
  "use strict";

  const PH = window.PH;
  const KEY = "ph-learn";

  function read() {
    try {
      const raw = localStorage.getItem(KEY);
      const parsed = raw ? JSON.parse(raw) : null;
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch (_) { return {}; }
  }

  function write(state) {
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (_) { /* noop */ }
  }

  function boxes() { return Array.from(document.querySelectorAll("[data-learn-id]")); }

  function update(state) {
    const all = boxes();
    const done = all.filter((box) => state[box.getAttribute("data-learn-id")]).length;
    all.forEach((box) => {
      box.checked = !!state[box.getAttribute("data-learn-id")];
      const item = box.closest("li");
      if (item) item.classList.toggle("is-done", box.checked);
    });
    const bar = document.querySelector("[data-learn-bar]");
    const label = document.querySelector("[data-learn-label]");
    const pct = all.length ? Math.round((done / all.length) * 100) : 0;
    if (bar) bar.style.width = pct + "%";
    if (label) label.textContent = done + " / " + all.length + " complete · " + pct + "%";
  }

  function init() {
    const all = boxes();
    if (!all.length) return;
    let state = read();
    update(state);
    all.forEach((box) => {
      box.addEventListener("change", () => {
        const id = box.getAttribute("data-learn-id");
        if (box.checked) state[id] = true;
        else delete state[id];
        write(state);
        update(state);
      });
    });
    const reset = document.querySelector("[data-learn-reset]");
    if (reset) reset.addEventListener("click", () => {
      state = {};
      write(state);
      update(state);
      PH.toast("learning progress reset");
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
