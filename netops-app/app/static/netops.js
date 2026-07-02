function norm(value) {
  return (value || "").toString().trim().toLowerCase();
}

function filterSwitches() {
  const input = document.querySelector("[data-switch-filter]");
  const list = document.querySelector("[data-switch-list]");

  if (!input || !list) return;

  const q = norm(input.value);
  const items = Array.from(list.querySelectorAll(".switch-item"));

  for (const item of items) {
    const text = norm(item.textContent);
    item.hidden = q.length > 0 && !text.includes(q);
  }
}

function clearSwitchFilter() {
  const input = document.querySelector("[data-switch-filter]");
  const list = document.querySelector("[data-switch-list]");

  if (input) {
    input.value = "";
    input.focus();
  }

  if (list) {
    const items = Array.from(list.querySelectorAll(".switch-item"));
    for (const item of items) {
      item.hidden = false;
    }
  }
}

function unitMultiplier(unit) {
  const u = norm(unit);

  if (u === "bps") return 1;
  if (u === "kbps") return 1000;
  if (u === "mbps") return 1000 * 1000;
  if (u === "gbps") return 1000 * 1000 * 1000;
  if (u === "tbps") return 1000 * 1000 * 1000 * 1000;

  return null;
}

function sortableValue(text) {
  const raw = (text || "").toString().trim();
  const lower = raw.toLowerCase();

  if (lower === "") {
    return { type: "empty", value: "" };
  }

  const rateMatch = lower.match(/^(-?[0-9]+(?:\.[0-9]+)?)\s*(bps|kbps|mbps|gbps|tbps)$/);
  if (rateMatch) {
    const mult = unitMultiplier(rateMatch[2]);
    return { type: "number", value: parseFloat(rateMatch[1]) * mult };
  }

  const pctMatch = lower.match(/^(-?[0-9]+(?:\.[0-9]+)?)%$/);
  if (pctMatch) {
    return { type: "number", value: parseFloat(pctMatch[1]) };
  }

  const numClean = lower.replace(/,/g, "");
  if (/^-?[0-9]+(?:\.[0-9]+)?$/.test(numClean)) {
    return { type: "number", value: parseFloat(numClean) };
  }

  if (lower === "up") {
    return { type: "status", value: 2 };
  }

  if (lower === "down") {
    return { type: "status", value: 1 };
  }

  return { type: "text", value: lower };
}

function compareSortable(aText, bText, direction) {
  const a = sortableValue(aText);
  const b = sortableValue(bText);

  if (a.type === "empty" && b.type !== "empty") return 1;
  if (a.type !== "empty" && b.type === "empty") return -1;
  if (a.type === "empty" && b.type === "empty") return 0;

  let result = 0;

  if ((a.type === "number" || a.type === "status") && (b.type === "number" || b.type === "status")) {
    result = a.value - b.value;
  } else {
    result = String(a.value).localeCompare(String(b.value), undefined, {
      numeric: true,
      sensitivity: "base"
    });
  }

  return direction === "desc" ? -result : result;
}

function clearSortIndicators(table) {
  const headers = table.querySelectorAll("th[data-sort-col]");
  for (const th of headers) {
    th.removeAttribute("data-sort-dir");
    const indicator = th.querySelector(".sort-indicator");
    if (indicator) {
      indicator.textContent = "sort";
    }
  }
}

function sortTableByHeader(th) {
  const table = th.closest("table");
  const tbody = table ? table.querySelector("tbody") : null;

  if (!table || !tbody) return;

  const colIndex = parseInt(th.getAttribute("data-sort-col") || "0", 10);
  const current = th.getAttribute("data-sort-dir") || "";
  const direction = current === "asc" ? "desc" : "asc";

  const rows = Array.from(tbody.querySelectorAll("tr")).filter((tr) => {
    return tr.querySelectorAll("td").length > 1;
  });

  const indexed = rows.map((row, index) => ({ row, index }));

  indexed.sort((a, b) => {
    const aCell = a.row.children[colIndex];
    const bCell = b.row.children[colIndex];

    const aText = aCell ? aCell.textContent : "";
    const bText = bCell ? bCell.textContent : "";

    const result = compareSortable(aText, bText, direction);
    if (result !== 0) return result;

    return a.index - b.index;
  });

  clearSortIndicators(table);

  th.setAttribute("data-sort-dir", direction);
  const indicator = th.querySelector(".sort-indicator");
  if (indicator) {
    indicator.textContent = direction;
  }

  for (const item of indexed) {
    tbody.appendChild(item.row);
  }
}

function initSortableTables() {
  const headers = document.querySelectorAll("table[data-sortable-table] th[data-sort-col]");

  for (const th of headers) {
    th.addEventListener("click", () => sortTableByHeader(th));

    th.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        sortTableByHeader(th);
      }
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const input = document.querySelector("[data-switch-filter]");
  if (input) {
    input.addEventListener("input", filterSwitches);
  }

  filterSwitches();
  initSortableTables();
});

/* DNS Status Dashboard polish */
document.addEventListener("DOMContentLoaded", function () {
  if (!window.location.pathname.endsWith("/dashboards/dns")) {
    return;
  }

  document.body.classList.add("dns-status-polish");

  document.querySelectorAll("table tbody tr").forEach(function (row) {
    const text = row.textContent.toUpperCase();

    if (text.includes("CRITICAL") || text.includes("BAD") || text.includes("FAIL")) {
      row.classList.add("critical-row");
    } else if (text.includes("WARN")) {
      row.classList.add("warn-row");
    } else if (text.includes("OK")) {
      row.classList.add("good-row");
    }

    row.querySelectorAll("td").forEach(function (cell) {
      const value = cell.textContent.trim().toUpperCase();

      if (value === "OK") {
        cell.classList.add("status-good");
      } else if (value === "WARN" || value === "WARNING") {
        cell.classList.add("status-warn");
      } else if (value === "BAD" || value === "FAIL" || value === "FAILED" || value === "CRITICAL") {
        cell.classList.add("status-critical");
      }
    });
  });
});

/* Time & DNS grouped internal/public sections */
document.addEventListener("DOMContentLoaded", function () {
  if (!window.location.pathname.endsWith("/dashboards/time-dns")) {
    return;
  }

  document.body.classList.add("time-dns-grouped");

  function cardTitle(card) {
    const h = card.querySelector("h2, h3, strong");
    return h ? h.textContent.trim().toLowerCase() : card.textContent.trim().toLowerCase();
  }

  function findHeading(text) {
    const want = text.toLowerCase();
    return Array.from(document.querySelectorAll("h1,h2,h3")).find(function (h) {
      return h.textContent.trim().toLowerCase() === want;
    });
  }

  function findCardGridAfterHeading(heading) {
    let el = heading ? heading.parentElement : null;

    while (el && el !== document.body) {
      let sib = el.nextElementSibling;
      while (sib) {
        const cards = Array.from(sib.children || []).filter(function (child) {
          return child.querySelector && child.querySelector("h2, h3, .ntp-card-head, .dns-card-head");
        });

        if (cards.length >= 2) {
          return sib;
        }

        sib = sib.nextElementSibling;
      }

      el = el.parentElement;
    }

    return null;
  }

  function subsection(title, note) {
    const wrap = document.createElement("div");
    wrap.className = "tdns-subsection";
    wrap.innerHTML = "<h3>" + title + "</h3><p>" + note + "</p>";
    return wrap;
  }

  function divider() {
    const d = document.createElement("div");
    d.className = "tdns-group-divider";
    return d;
  }

  function makeGrid(cls, cards) {
    const grid = document.createElement("div");
    grid.className = "tdns-group-grid " + cls;
    cards.forEach(function (card) {
      grid.appendChild(card);
    });
    return grid;
  }

  function regroupNtp() {
    const heading = findHeading("NTP / Time Drift");
    const grid = findCardGridAfterHeading(heading);
    if (!heading || !grid || grid.dataset.grouped === "1") {
      return;
    }

    const cards = Array.from(grid.children).filter(function (child) {
      return child.querySelector && child.querySelector("h2, h3, strong");
    });

    const internal = [];
    const external = [];

    cards.forEach(function (card) {
      const t = cardTitle(card);

      if (
        t.includes("cloudflare") ||
        t.includes("google") ||
        t.includes("aws") ||
        t.includes("nist")
      ) {
        external.push(card);
      } else {
        internal.push(card);
      }
    });

    if (!internal.length || !external.length) {
      return;
    }

    const parent = grid.parentElement;
    const marker = document.createElement("div");

    parent.insertBefore(marker, grid);
    grid.remove();

    parent.insertBefore(subsection("Middlebury NTP", "Primary service and campus NTP appliances."), marker);
    parent.insertBefore(divider(), marker);
    parent.insertBefore(makeGrid("tdns-ntp-internal", internal), marker);

    parent.insertBefore(subsection("External NTP References", "Comparison only. These do not drive internal service state."), marker);
    parent.insertBefore(divider(), marker);
    parent.insertBefore(makeGrid("tdns-ntp-external", external), marker);

    marker.remove();
  }

  function regroupDns() {
    const heading = findHeading("DNS Resolver Health");
    const grid = findCardGridAfterHeading(heading);
    if (!heading || !grid || grid.dataset.grouped === "1") {
      return;
    }

    const cards = Array.from(grid.children).filter(function (child) {
      return child.querySelector && child.querySelector("h2, h3, strong");
    });

    const internal = [];
    const external = [];

    cards.forEach(function (card) {
      const t = cardTitle(card);

      if (t.includes("cloudflare") || t.includes("google")) {
        external.push(card);
      } else {
        internal.push(card);
      }
    });

    if (!internal.length || !external.length) {
      return;
    }

    const parent = grid.parentElement;
    const marker = document.createElement("div");

    parent.insertBefore(marker, grid);
    grid.remove();

    parent.insertBefore(subsection("Middlebury DNS Resolvers", "Campus and SOLIDserver DNS resolver checks."), marker);
    parent.insertBefore(divider(), marker);
    parent.insertBefore(makeGrid("tdns-dns-internal", internal), marker);

    parent.insertBefore(subsection("Public DNS References", "External resolver comparison only."), marker);
    parent.insertBefore(divider(), marker);
    parent.insertBefore(makeGrid("tdns-dns-public", external), marker);

    marker.remove();
  }

  regroupNtp();
  regroupDns();
});

/* Time & DNS grouped internal/public sections */
document.addEventListener("DOMContentLoaded", function () {
  if (!window.location.pathname.endsWith("/dashboards/time-dns")) {
    return;
  }

  document.body.classList.add("time-dns-grouped");

  function cardTitle(card) {
    const h = card.querySelector("h2, h3, strong");
    return h ? h.textContent.trim().toLowerCase() : card.textContent.trim().toLowerCase();
  }

  function findHeading(text) {
    const want = text.toLowerCase();
    return Array.from(document.querySelectorAll("h1,h2,h3")).find(function (h) {
      return h.textContent.trim().toLowerCase() === want;
    });
  }

  function findCardGridAfterHeading(heading) {
    let el = heading ? heading.parentElement : null;

    while (el && el !== document.body) {
      let sib = el.nextElementSibling;
      while (sib) {
        const cards = Array.from(sib.children || []).filter(function (child) {
          return child.querySelector && child.querySelector("h2, h3, .ntp-card-head, .dns-card-head");
        });

        if (cards.length >= 2) {
          return sib;
        }

        sib = sib.nextElementSibling;
      }

      el = el.parentElement;
    }

    return null;
  }

  function subsection(title, note) {
    const wrap = document.createElement("div");
    wrap.className = "tdns-subsection";
    wrap.innerHTML = "<h3>" + title + "</h3><p>" + note + "</p>";
    return wrap;
  }

  function divider() {
    const d = document.createElement("div");
    d.className = "tdns-group-divider";
    return d;
  }

  function makeGrid(cls, cards) {
    const grid = document.createElement("div");
    grid.className = "tdns-group-grid " + cls;
    cards.forEach(function (card) {
      grid.appendChild(card);
    });
    return grid;
  }

  function regroupNtp() {
    const heading = findHeading("NTP / Time Drift");
    const grid = findCardGridAfterHeading(heading);
    if (!heading || !grid || grid.dataset.grouped === "1") {
      return;
    }

    const cards = Array.from(grid.children).filter(function (child) {
      return child.querySelector && child.querySelector("h2, h3, strong");
    });

    const internal = [];
    const external = [];

    cards.forEach(function (card) {
      const t = cardTitle(card);

      if (
        t.includes("cloudflare") ||
        t.includes("google") ||
        t.includes("aws") ||
        t.includes("nist")
      ) {
        external.push(card);
      } else {
        internal.push(card);
      }
    });

    if (!internal.length || !external.length) {
      return;
    }

    const parent = grid.parentElement;
    const marker = document.createElement("div");

    parent.insertBefore(marker, grid);
    grid.remove();

    parent.insertBefore(subsection("Middlebury NTP", "Primary service and campus NTP appliances."), marker);
    parent.insertBefore(divider(), marker);
    parent.insertBefore(makeGrid("tdns-ntp-internal", internal), marker);

    parent.insertBefore(subsection("External NTP References", "Comparison only. These do not drive internal service state."), marker);
    parent.insertBefore(divider(), marker);
    parent.insertBefore(makeGrid("tdns-ntp-external", external), marker);

    marker.remove();
  }

  function regroupDns() {
    const heading = findHeading("DNS Resolver Health");
    const grid = findCardGridAfterHeading(heading);
    if (!heading || !grid || grid.dataset.grouped === "1") {
      return;
    }

    const cards = Array.from(grid.children).filter(function (child) {
      return child.querySelector && child.querySelector("h2, h3, strong");
    });

    const internal = [];
    const external = [];

    cards.forEach(function (card) {
      const t = cardTitle(card);

      if (t.includes("cloudflare") || t.includes("google")) {
        external.push(card);
      } else {
        internal.push(card);
      }
    });

    if (!internal.length || !external.length) {
      return;
    }

    const parent = grid.parentElement;
    const marker = document.createElement("div");

    parent.insertBefore(marker, grid);
    grid.remove();

    parent.insertBefore(subsection("Middlebury DNS Resolvers", "Campus and SOLIDserver DNS resolver checks."), marker);
    parent.insertBefore(divider(), marker);
    parent.insertBefore(makeGrid("tdns-dns-internal", internal), marker);

    parent.insertBefore(subsection("Public DNS References", "External resolver comparison only."), marker);
    parent.insertBefore(divider(), marker);
    parent.insertBefore(makeGrid("tdns-dns-public", external), marker);

    marker.remove();
  }

  regroupNtp();
  regroupDns();
});

/* Finished top navigation menus */
document.addEventListener("DOMContentLoaded", function () {
  const base = window.location.pathname.startsWith("/netops-v4") ? "/netops-v4" : "";

  const menus = {
    "Dashboards": [
      {
        section: "Health",
        items: [
          ["Time & DNS Health", "/dashboards/time-dns"],
          ["NTP Status", "/dashboards/ntp"],
          ["DNS Status", "/dashboards/dns"],
          ["Status Overview", "/dashboards/time-dns"]
        ]
      },
      {
        section: "Operational",
        items: [
          ["All Dashboards", "/dashboards"],
          ["Device", "/dashboards/device"],
          ["Events", "/dashboards/events"],
          ["Interface", "/dashboards/interface"]
        ]
      }
    ],
    "Reports": [
      {
        section: "Reports",
        items: [
          ["Interface Statistics", "/reports/interface-statistics"]
        ]
      }
    ]
  };

  function hrefFor(path) {
    if (path.startsWith("http")) {
      return path;
    }
    return base + path;
  }

  function isActive(path) {
    const full = hrefFor(path);
    return window.location.pathname === full || window.location.pathname.endsWith(path);
  }

  function buildPanel(groups) {
    const panel = document.createElement("div");
    panel.className = "netops-complete-menu-panel";

    groups.forEach(function (group) {
      const section = document.createElement("div");
      section.className = "netops-complete-menu-section";
      section.textContent = group.section;
      panel.appendChild(section);

      group.items.forEach(function (item) {
        const a = document.createElement("a");
        a.href = hrefFor(item[1]);
        a.textContent = item[0];

        if (isActive(item[1])) {
          a.className = "active";
        }

        panel.appendChild(a);
      });
    });

    return panel;
  }

  function findTopLabel(label) {
    const candidates = Array.from(document.querySelectorAll("a, button, span, div"))
      .filter(function (el) {
        const rect = el.getBoundingClientRect();
        const text = (el.textContent || "").trim();

        return (
          text === label &&
          rect.width > 0 &&
          rect.height > 0 &&
          rect.top < 100
        );
      });

    if (!candidates.length) {
      return null;
    }

    candidates.sort(function (a, b) {
      const ar = a.getBoundingClientRect();
      const br = b.getBoundingClientRect();
      return ar.top - br.top || ar.left - br.left;
    });

    return candidates[0];
  }

  function attachMenu(label, groups) {
    const labelEl = findTopLabel(label);

    if (!labelEl) {
      return;
    }

    let root =
      labelEl.closest("li") ||
      labelEl.closest(".dropdown") ||
      labelEl.closest(".nav-item") ||
      labelEl.parentElement;

    if (!root || root === document.body || root === document.documentElement) {
      return;
    }

    root.classList.add("netops-complete-menu-root");

    Array.from(root.children).forEach(function (child) {
      if (
        child !== labelEl &&
        !child.classList.contains("netops-complete-menu-panel") &&
        child.querySelector &&
        child.querySelector("a")
      ) {
        child.style.display = "none";
      }
    });

    const oldPanel = root.querySelector(".netops-complete-menu-panel");
    if (oldPanel) {
      oldPanel.remove();
    }

    root.appendChild(buildPanel(groups));

    labelEl.addEventListener("click", function (event) {
      if (window.matchMedia("(hover: none)").matches) {
        event.preventDefault();
        root.classList.toggle("menu-open");
      }
    });
  }

  Object.keys(menus).forEach(function (label) {
    attachMenu(label, menus[label]);
  });
});

/* Finished top navigation menus */
document.addEventListener("DOMContentLoaded", function () {
  const base = window.location.pathname.startsWith("/netops-v4") ? "/netops-v4" : "";

  const menus = {
    "Dashboards": [
      {
        section: "Health",
        items: [
          ["Time & DNS Health", "/dashboards/time-dns"],
          ["NTP Status", "/dashboards/ntp"],
          ["DNS Status", "/dashboards/dns"],
          ["Status Overview", "/dashboards/time-dns"]
        ]
      },
      {
        section: "Operational",
        items: [
          ["All Dashboards", "/dashboards"],
          ["Device", "/dashboards/device"],
          ["Events", "/dashboards/events"],
          ["Interface", "/dashboards/interface"]
        ]
      }
    ],
    "Reports": [
      {
        section: "Reports",
        items: [
          ["Interface Statistics", "/reports/interface-statistics"]
        ]
      }
    ]
  };

  function hrefFor(path) {
    if (path.startsWith("http")) {
      return path;
    }
    return base + path;
  }

  function isActive(path) {
    const full = hrefFor(path);
    return window.location.pathname === full || window.location.pathname.endsWith(path);
  }

  function buildPanel(groups) {
    const panel = document.createElement("div");
    panel.className = "netops-complete-menu-panel";

    groups.forEach(function (group) {
      const section = document.createElement("div");
      section.className = "netops-complete-menu-section";
      section.textContent = group.section;
      panel.appendChild(section);

      group.items.forEach(function (item) {
        const a = document.createElement("a");
        a.href = hrefFor(item[1]);
        a.textContent = item[0];

        if (isActive(item[1])) {
          a.className = "active";
        }

        panel.appendChild(a);
      });
    });

    return panel;
  }

  function findTopLabel(label) {
    const candidates = Array.from(document.querySelectorAll("a, button, span, div"))
      .filter(function (el) {
        const rect = el.getBoundingClientRect();
        const text = (el.textContent || "").trim();

        return (
          text === label &&
          rect.width > 0 &&
          rect.height > 0 &&
          rect.top < 100
        );
      });

    if (!candidates.length) {
      return null;
    }

    candidates.sort(function (a, b) {
      const ar = a.getBoundingClientRect();
      const br = b.getBoundingClientRect();
      return ar.top - br.top || ar.left - br.left;
    });

    return candidates[0];
  }

  function attachMenu(label, groups) {
    const labelEl = findTopLabel(label);

    if (!labelEl) {
      return;
    }

    let root =
      labelEl.closest("li") ||
      labelEl.closest(".dropdown") ||
      labelEl.closest(".nav-item") ||
      labelEl.parentElement;

    if (!root || root === document.body || root === document.documentElement) {
      return;
    }

    root.classList.add("netops-complete-menu-root");

    Array.from(root.children).forEach(function (child) {
      if (
        child !== labelEl &&
        !child.classList.contains("netops-complete-menu-panel") &&
        child.querySelector &&
        child.querySelector("a")
      ) {
        child.style.display = "none";
      }
    });

    const oldPanel = root.querySelector(".netops-complete-menu-panel");
    if (oldPanel) {
      oldPanel.remove();
    }

    root.appendChild(buildPanel(groups));

    labelEl.addEventListener("click", function (event) {
      if (window.matchMedia("(hover: none)").matches) {
        event.preventDefault();
        root.classList.toggle("menu-open");
      }
    });
  }

  Object.keys(menus).forEach(function (label) {
    attachMenu(label, menus[label]);
  });
});

/* Mark all original/native top nav dropdowns for dark styling */
document.addEventListener("DOMContentLoaded", function () {
  const labels = ["Dashboards", "Reports", "Tools", "Admin", "New", "PDF"];

  function findTopLabel(label) {
    const candidates = Array.from(document.querySelectorAll("a, button, span, div"))
      .filter(function (el) {
        const rect = el.getBoundingClientRect();
        const text = (el.textContent || "").trim();

        return (
          text === label &&
          rect.width > 0 &&
          rect.height > 0 &&
          rect.top < 120
        );
      });

    if (!candidates.length) {
      return null;
    }

    candidates.sort(function (a, b) {
      const ar = a.getBoundingClientRect();
      const br = b.getBoundingClientRect();
      return ar.top - br.top || ar.left - br.left;
    });

    return candidates[0];
  }

  labels.forEach(function (label) {
    const labelEl = findTopLabel(label);
    if (!labelEl) {
      return;
    }

    const root =
      labelEl.closest("li") ||
      labelEl.closest(".dropdown") ||
      labelEl.closest(".nav-item") ||
      labelEl.parentElement;

    if (!root || root === document.body || root === document.documentElement) {
      return;
    }

    root.classList.add("netops-menu-root-dark");

    Array.from(root.children).forEach(function (child) {
      if (child === labelEl || child.classList.contains("netops-complete-menu-panel")) {
        return;
      }

      if (child.querySelector && child.querySelector("a")) {
        child.classList.add("netops-native-menu-panel");
      }
    });

    root.querySelectorAll("ul, div").forEach(function (panel) {
      if (panel.classList.contains("netops-complete-menu-panel")) {
        return;
      }

      const links = panel.querySelectorAll("a");
      const rect = panel.getBoundingClientRect();

      if (links.length >= 1 && rect.top < 180) {
        panel.classList.add("netops-native-menu-panel");
      }
    });
  });
});

/* Mark all original/native top nav dropdowns for dark styling */
document.addEventListener("DOMContentLoaded", function () {
  const labels = ["Dashboards", "Reports", "Tools", "Admin", "New", "PDF"];

  function findTopLabel(label) {
    const candidates = Array.from(document.querySelectorAll("a, button, span, div"))
      .filter(function (el) {
        const rect = el.getBoundingClientRect();
        const text = (el.textContent || "").trim();

        return (
          text === label &&
          rect.width > 0 &&
          rect.height > 0 &&
          rect.top < 120
        );
      });

    if (!candidates.length) {
      return null;
    }

    candidates.sort(function (a, b) {
      const ar = a.getBoundingClientRect();
      const br = b.getBoundingClientRect();
      return ar.top - br.top || ar.left - br.left;
    });

    return candidates[0];
  }

  labels.forEach(function (label) {
    const labelEl = findTopLabel(label);
    if (!labelEl) {
      return;
    }

    const root =
      labelEl.closest("li") ||
      labelEl.closest(".dropdown") ||
      labelEl.closest(".nav-item") ||
      labelEl.parentElement;

    if (!root || root === document.body || root === document.documentElement) {
      return;
    }

    root.classList.add("netops-menu-root-dark");

    Array.from(root.children).forEach(function (child) {
      if (child === labelEl || child.classList.contains("netops-complete-menu-panel")) {
        return;
      }

      if (child.querySelector && child.querySelector("a")) {
        child.classList.add("netops-native-menu-panel");
      }
    });

    root.querySelectorAll("ul, div").forEach(function (panel) {
      if (panel.classList.contains("netops-complete-menu-panel")) {
        return;
      }

      const links = panel.querySelectorAll("a");
      const rect = panel.getBoundingClientRect();

      if (links.length >= 1 && rect.top < 180) {
        panel.classList.add("netops-native-menu-panel");
      }
    });
  });
});

/* Redirect old placeholder Status dashboard */
document.addEventListener("DOMContentLoaded", function () {
  if (window.location.pathname.endsWith("/dashboards/status")) {
    const base = window.location.pathname.startsWith("/netops-v4") ? "/netops-v4" : "";
    window.location.replace(base + "/dashboards/time-dns");
  }
});
