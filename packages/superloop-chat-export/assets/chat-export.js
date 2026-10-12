// The reading mode and the opening of a linked record's disclosures.
// Loaded in the page head, so the stored mode is known before the body is
// parsed; without it the pages read the same in the default mode.
"use strict";
(() => {
  const KEY = "chat-export.mode";
  const root = document.documentElement;
  let mode = "all";
  try {
    if (localStorage.getItem(KEY) === "prompts") mode = "prompts";
  } catch (refused) {
    mode = "all";
  }
  // Until the disclosures exist, a class on the root keeps responses shut.
  if (mode === "prompts") root.classList.add("prompts-pending");

  const apply = () => {
    for (const response of document.querySelectorAll("details.response")) {
      response.open = mode !== "prompts";
    }
    if (mode === "prompts") {
      for (const run of document.querySelectorAll("details.run")) run.open = false;
    }
    for (const button of document.querySelectorAll("button.mode")) {
      button.textContent = mode === "prompts" ? "Show everything" : "Prompts only";
      button.classList.toggle("active", mode === "prompts");
    }
  };

  const reveal = () => {
    let id = location.hash.slice(1);
    try {
      id = decodeURIComponent(id);
    } catch (malformed) {
      // A bad escape keeps the raw fragment, which names no record.
    }
    const target = id && document.getElementById(id);
    for (let node = target && target.parentElement; node; node = node.parentElement) {
      if (node.tagName === "DETAILS") node.open = true;
    }
  };

  // A generated frame is named for its main page; a reused top-level context can retain another name.
  // Its URL has no fragment, so loading it cannot navigate to a row.
  const currentPage = () => {
    if (window.self === window.top) return;
    const name = window.name;
    if (!/^page-[1-9][0-9]*$/.test(name)) return;
    let frame;
    try {
      frame = window.frameElement;
    } catch (inaccessible) {
      frame = null;
    }
    if (frame) {
      if (
        !frame.matches("nav.pager > details.pages > iframe") ||
        frame.getAttribute("src") !== "pages.html" ||
        frame.getAttribute("name") !== name
      ) return;
    }
    const row = document.getElementById(name);
    const scroller = document.scrollingElement;
    if (!row?.matches("main.list table.pages tr") || !scroller) return;
    row.classList.add("current-page");
    row.querySelector("a")?.setAttribute("aria-current", "page");
    const box = row.getBoundingClientRect();
    scroller.scrollTop += box.top - (scroller.clientHeight - box.height) / 2;
  };

  document.addEventListener("DOMContentLoaded", () => {
    apply();
    root.classList.remove("prompts-pending");
    for (const button of document.querySelectorAll("button.mode")) {
      button.hidden = false;
      button.addEventListener("click", () => {
        mode = mode === "prompts" ? "all" : "prompts";
        try {
          localStorage.setItem(KEY, mode);
        } catch (refused) {
          // The mode then lasts for this page only.
        }
        apply();
      });
    }
    reveal();
    currentPage();
  });
  window.addEventListener("hashchange", reveal);
})();
