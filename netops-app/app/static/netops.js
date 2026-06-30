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
