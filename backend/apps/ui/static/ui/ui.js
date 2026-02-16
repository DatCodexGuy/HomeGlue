(() => {
  // If JS fails to parse/execute, CSS will keep `.reveal` visible (see ui.css).
  document.documentElement.setAttribute("data-js", "1");

  // Staggered reveal for sections.
  const nodes = Array.from(document.querySelectorAll(".reveal"));
  nodes.forEach((el, i) => {
    const delay = Math.min(i * 55, 240);
    setTimeout(() => el.classList.add("is-in"), delay);
  });

  // Click-to-copy blocks.
  document.addEventListener("click", async (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    const copy = t.closest("[data-copy]");
    if (!copy) return;
    const text = (copy.textContent || "").trim();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      copy.setAttribute("data-copied", "1");
      setTimeout(() => copy.removeAttribute("data-copied"), 800);
    } catch {
      // ignore
    }
  });

  // Mobile nav drawer toggle.
  const body = document.body;
  const menuBtn = document.querySelector(".js-menu");
  const backdrop = document.querySelector(".js-backdrop");
  const side = document.querySelector(".js-side");

  const closeNav = () => body.classList.remove("nav-open");
  const toggleNav = () => body.classList.toggle("nav-open");

  if (menuBtn && side) {
    menuBtn.addEventListener("click", toggleNav);
  }
  if (backdrop) {
    backdrop.addEventListener("click", closeNav);
  }
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeNav();
  });

  // Relationship-count pills: allow click inside a row link.
  const go = (href) => {
    if (!href) return;
    window.location.href = href;
  };
  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    const pill = t.closest(".pill--click[data-href]");
    if (!pill) return;
    e.preventDefault();
    e.stopPropagation();
    go(pill.getAttribute("data-href"));
  });
  document.addEventListener("keydown", (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    const pill = t.closest(".pill--click[data-href]");
    if (!pill) return;
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    e.stopPropagation();
    go(pill.getAttribute("data-href"));
  });

  // Bulk selection toolbars on list pages.
  const bulkRoots = Array.from(document.querySelectorAll("form.js-bulk"));
  bulkRoots.forEach((root) => {
    const all = root.querySelector(".js-bulk-all");
    const items = () => Array.from(root.querySelectorAll(".js-bulk-item"));
    const bar = root.querySelector(".js-bulkbar");
    const count = root.querySelector(".js-bulk-count");
    const del = root.querySelector(".js-bulk-delete");

    const refresh = () => {
      const checked = items().filter((i) => i instanceof HTMLInputElement && i.checked).length;
      if (count) count.textContent = String(checked);
      if (bar) {
        if (checked > 0) bar.classList.add("is-on");
        else bar.classList.remove("is-on");
      }
      if (all && all instanceof HTMLInputElement) {
        const it = items().filter((i) => i instanceof HTMLInputElement);
        const allChecked = it.length > 0 && it.every((i) => i.checked);
        const anyChecked = it.some((i) => i.checked);
        all.indeterminate = anyChecked && !allChecked;
        all.checked = allChecked;
      }
    };

    if (all && all instanceof HTMLInputElement) {
      all.addEventListener("change", () => {
        const checked = all.checked;
        items().forEach((i) => {
          if (i instanceof HTMLInputElement) i.checked = checked;
        });
        refresh();
      });
    }
    items().forEach((i) => {
      if (!(i instanceof HTMLInputElement)) return;
      i.addEventListener("change", refresh);
      i.addEventListener("click", (e) => e.stopPropagation());
    });

    if (del) {
      del.addEventListener("click", (e) => {
        const n = items().filter((i) => i instanceof HTMLInputElement && i.checked).length;
        if (n <= 0) return;
        const verb = (del.textContent || "").trim() || "Delete";
        const isArchive = /archive/i.test(verb) || (del instanceof HTMLButtonElement && del.value === "archive");
        const msg = isArchive
          ? `${verb} ${n} item(s)? You can restore later.`
          : `${verb} ${n} item(s)? This cannot be undone.`;
        if (!window.confirm(msg)) {
          e.preventDefault();
          e.stopPropagation();
        }
      });
    }

    refresh();
  });

  // Make bulk list rows clickable, without breaking checkboxes/pills.
  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.closest("a,button,input,select,textarea,.pill--click")) return;
    const row = t.closest(".row--click[data-href]");
    if (!row) return;
    const href = row.getAttribute("data-href");
    if (href) window.location.href = href;
  });

  // Theme toggle (persist in localStorage).
  const themeBtns = Array.from(document.querySelectorAll(".js-theme"));
  const themeLabel = document.querySelector(".js-theme-label");
  const getTheme = () => document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
  const applyTheme = (t) => {
    if (t === "dark") document.documentElement.setAttribute("data-theme", "dark");
    else document.documentElement.removeAttribute("data-theme");
    if (themeLabel) themeLabel.textContent = (t === "dark") ? "Light" : "Dark";
    const use = (t === "dark") ? "#i-sun" : "#i-moon";
    themeBtns.forEach((b) => {
      const u = b.querySelector("use");
      if (u) u.setAttribute("href", use);
    });
  };
  try { applyTheme(localStorage.getItem("homeglue_theme") || getTheme()); } catch {}
  themeBtns.forEach((b) => {
    b.addEventListener("click", () => {
      const next = (getTheme() === "dark") ? "light" : "dark";
      try { localStorage.setItem("homeglue_theme", next); } catch {}
      applyTheme(next);
    });
  });

  // Markdown editor helper (Docs, Notes, etc.): toolbar + safe preview.
  const getCookie = (name) => {
    const all = `; ${document.cookie || ""}`;
    const parts = all.split(`; ${name}=`);
    if (parts.length !== 2) return "";
    const v = parts.pop().split(";").shift();
    try { return decodeURIComponent(v || ""); } catch { return v || ""; }
  };
  const csrfToken = () => getCookie("csrftoken");

  const surround = (ta, before, after) => {
    if (!(ta instanceof HTMLTextAreaElement)) return;
    const start = ta.selectionStart || 0;
    const end = ta.selectionEnd || 0;
    const val = ta.value || "";
    const sel = val.slice(start, end) || "";
    const next = val.slice(0, start) + before + sel + after + val.slice(end);
    ta.value = next;
    const caret = start + before.length + sel.length + after.length;
    ta.focus();
    ta.setSelectionRange(caret, caret);
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  };

  const prefixLine = (ta, prefix) => {
    if (!(ta instanceof HTMLTextAreaElement)) return;
    const start = ta.selectionStart || 0;
    const val = ta.value || "";
    const lineStart = val.lastIndexOf("\n", start - 1) + 1;
    ta.value = val.slice(0, lineStart) + prefix + val.slice(lineStart);
    const caret = start + prefix.length;
    ta.focus();
    ta.setSelectionRange(caret, caret);
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  };

  const makeMdToolbar = (ta) => {
    const bar = document.createElement("div");
    bar.className = "mdedit__bar";

    const btn = (label, title, onClick) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "mdedit__btn";
      b.textContent = label;
      b.title = title;
      b.addEventListener("click", (e) => {
        e.preventDefault();
        onClick();
      });
      return b;
    };

    const style = document.createElement("select");
    style.className = "mdedit__select";
    style.innerHTML = `
      <option value="">Style</option>
      <option value="h2">Heading 2</option>
      <option value="h3">Heading 3</option>
      <option value="quote">Quote</option>
      <option value="ul">Bulleted list</option>
      <option value="ol">Numbered list</option>
      <option value="codeblock">Code block</option>
    `;
    style.addEventListener("change", () => {
      const v = style.value;
      style.value = "";
      if (v === "h2") prefixLine(ta, "## ");
      else if (v === "h3") prefixLine(ta, "### ");
      else if (v === "quote") prefixLine(ta, "> ");
      else if (v === "ul") prefixLine(ta, "- ");
      else if (v === "ol") prefixLine(ta, "1. ");
      else if (v === "codeblock") surround(ta, "```\n", "\n```\n");
    });

    const previewBtn = btn("Preview", "Render Markdown preview", () => {});
    bar.appendChild(style);
    bar.appendChild(btn("B", "Bold", () => surround(ta, "**", "**")));
    bar.appendChild(btn("I", "Italic", () => surround(ta, "*", "*")));
    bar.appendChild(btn("`", "Inline code", () => surround(ta, "`", "`")));
    bar.appendChild(btn("Link", "Insert link", () => surround(ta, "[", "](https://example.com)")));
    bar.appendChild(previewBtn);

    const preview = document.createElement("div");
    preview.className = "mdedit__preview md";
    preview.style.display = "none";

    const setMode = (mode) => {
      if (mode === "preview") {
        preview.style.display = "";
        ta.style.display = "none";
        previewBtn.textContent = "Edit";
      } else {
        preview.style.display = "none";
        ta.style.display = "";
        previewBtn.textContent = "Preview";
      }
    };

    const refreshPreview = async () => {
      preview.innerHTML = '<div class="muted">Rendering...</div>';
      try {
        const body = new URLSearchParams();
        body.set("text", ta.value || "");
        const r = await fetch("/app/markdown/preview/", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", "X-CSRFToken": csrfToken() },
          body: body.toString(),
        });
        if (!r.ok) throw new Error("preview failed");
        const data = await r.json();
        preview.innerHTML = (data && data.html) ? data.html : "";
      } catch {
        preview.innerHTML = '<div class="muted">Preview unavailable.</div>';
      }
    };

    previewBtn.addEventListener("click", async () => {
      const inPreview = preview.style.display !== "none";
      if (!inPreview) {
        setMode("preview");
        await refreshPreview();
      } else {
        setMode("edit");
      }
    });

    ta.addEventListener("input", () => {
      // If the user edits while preview is visible (e.g. toggled by CSS), keep it fresh.
      if (preview.style.display !== "none") refreshPreview();
    });

    return { bar, preview };
  };

  const mdTextareas = Array.from(document.querySelectorAll("textarea.js-md"));
  mdTextareas.forEach((ta) => {
    if (!(ta instanceof HTMLTextAreaElement)) return;
    if (ta.dataset.mdReady === "1") return;
    ta.dataset.mdReady = "1";
    const wrap = document.createElement("div");
    wrap.className = "mdedit";
    const { bar, preview } = makeMdToolbar(ta);
    ta.parentNode && ta.parentNode.insertBefore(wrap, ta);
    wrap.appendChild(bar);
    wrap.appendChild(ta);
    wrap.appendChild(preview);
  });

  // ACL UI: show/hide allowed_users based on visibility.
  const refreshAclFields = (form) => {
    if (!(form instanceof HTMLFormElement)) return;
    const vis = form.querySelector('select[name="visibility"]');
    const allowed = form.querySelector('select[name="allowed_users"]');
    if (!(vis instanceof HTMLSelectElement) || !(allowed instanceof HTMLSelectElement)) return;
    const wrap = allowed.closest("p");
    const isShared = (vis.value || "").toLowerCase() === "shared";
    if (wrap) wrap.style.display = isShared ? "" : "none";
    allowed.disabled = !isShared;
  };

  Array.from(document.querySelectorAll("form")).forEach((f) => {
    refreshAclFields(f);
    const vis = f.querySelector('select[name="visibility"]');
    if (vis) {
      vis.addEventListener("change", () => refreshAclFields(f));
    }
  });

  // Command palette (Ctrl+K / /).
  const cmdkModal = document.querySelector(".js-cmdk-modal");
  const cmdkInput = document.querySelector(".js-cmdk-input");
  const cmdkList = document.querySelector(".js-cmdk-list");
  const cmdkOpenBtns = Array.from(document.querySelectorAll(".js-cmdk"));
  const cmdkCloseBtns = Array.from(document.querySelectorAll(".js-cmdk-close"));
  let cmdkItems = [];
  let cmdkActive = 0;
  let cmdkTimer = null;

  const renderCmdk = () => {
    if (!cmdkList) return;
    cmdkList.innerHTML = "";
    if (!cmdkItems.length) {
      const empty = document.createElement("div");
      empty.className = "cmdk__item";
      empty.innerHTML = `<div class="cmdk__itemType"><span class="pill pill--tiny">info</span></div><div class="cmdk__itemMain"><div class="cmdk__itemLabel">No results</div><div class="cmdk__itemMeta">Try a different query.</div></div>`;
      cmdkList.appendChild(empty);
      return;
    }
    let lastSection = null;
    cmdkItems.forEach((it, i) => {
      const section = it.section || null;
      if (section && section !== lastSection) {
        lastSection = section;
        const h = document.createElement("div");
        h.className = "cmdk__section";
        h.textContent = section;
        cmdkList.appendChild(h);
      }
      const a = document.createElement("a");
      a.className = "cmdk__item" + (i === cmdkActive ? " is-active" : "");
      a.href = it.url || "#";
      a.innerHTML = `
        <div class="cmdk__itemType"><span class="pill pill--tiny">${it.type}</span></div>
        <div class="cmdk__itemMain">
          <div class="cmdk__itemLabel">${it.label || ""}</div>
          <div class="cmdk__itemMeta">${it.meta || ""}</div>
        </div>
      `;
      a.addEventListener("mouseenter", () => {
        cmdkActive = i;
        renderCmdk();
      });
      cmdkList.appendChild(a);
    });
  };

  const fetchCmdk = async (q) => {
    if (!cmdkList) return;
    const url = `/app/quick/?q=${encodeURIComponent(q || "")}`;
    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) throw new Error("fetch failed");
    const data = await r.json();
    cmdkItems = Array.isArray(data.items) ? data.items : [];
    cmdkActive = 0;
    renderCmdk();
  };

  const openCmdk = async (prefill) => {
    if (!cmdkModal || !cmdkInput) return;
    cmdkModal.classList.add("is-on");
    cmdkModal.setAttribute("aria-hidden", "false");
    cmdkInput.value = prefill || "";
    cmdkInput.focus();
    try { await fetchCmdk(cmdkInput.value); } catch { renderCmdk(); }
  };
  const closeCmdk = () => {
    if (!cmdkModal) return;
    cmdkModal.classList.remove("is-on");
    cmdkModal.setAttribute("aria-hidden", "true");
  };

  cmdkOpenBtns.forEach((b) => b.addEventListener("click", () => openCmdk("")));
  cmdkCloseBtns.forEach((b) => b.addEventListener("click", closeCmdk));
  if (cmdkModal) {
    cmdkModal.addEventListener("click", (e) => {
      const t = e.target;
      if (!(t instanceof HTMLElement)) return;
      if (t.classList.contains("cmdk__backdrop")) closeCmdk();
    });
  }
  if (cmdkInput) {
    cmdkInput.addEventListener("input", () => {
      if (cmdkTimer) window.clearTimeout(cmdkTimer);
      cmdkTimer = window.setTimeout(() => fetchCmdk(cmdkInput.value).catch(() => {}), 120);
    });
    cmdkInput.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        closeCmdk();
        return;
      }
      if (e.key === "ArrowDown") {
        e.preventDefault();
        cmdkActive = Math.min(cmdkActive + 1, Math.max(cmdkItems.length - 1, 0));
        renderCmdk();
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        cmdkActive = Math.max(cmdkActive - 1, 0);
        renderCmdk();
        return;
      }
      if (e.key === "Enter") {
        const it = cmdkItems[cmdkActive];
        if (it && it.url) {
          window.location.href = it.url;
        }
      }
    });
  }
  window.addEventListener("keydown", (e) => {
    const t = e.target;
    const tag = t && t instanceof HTMLElement ? t.tagName.toLowerCase() : "";
    const typing = tag === "input" || tag === "textarea" || (t && t instanceof HTMLElement && t.isContentEditable);
    if (typing) return;

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openCmdk("");
      return;
    }
    if (e.key === "/") {
      e.preventDefault();
      openCmdk("");
      return;
    }
    if (e.key === "Escape") closeCmdk();
  });
})();
