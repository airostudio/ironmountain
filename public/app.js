// Playground UI. Results are rendered with DOM APIs (textContent), never innerHTML:
// findings echo back user-supplied code.
(function () {
  const $ = (id) => document.getElementById(id);
  const examples = window.IM_EXAMPLES || [];
  const select = $("example");
  const code = $("code");
  const filename = $("filename");

  examples.forEach((ex, i) => {
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = ex.label;
    select.appendChild(opt);
  });

  const load = (i) => {
    const ex = examples[i];
    if (!ex) return;
    code.value = ex.code;
    filename.value = ex.filename;
  };
  select.addEventListener("change", () => {
    if (select.value !== "") load(Number(select.value));
  });
  code.addEventListener("input", () => {
    select.value = "";
  });
  select.value = "0";
  load(0);

  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = $(btn.getAttribute("data-copy")).textContent;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "Copied";
      } catch {
        btn.textContent = "Select & copy";
      }
      setTimeout(() => (btn.textContent = "Copy"), 1500);
    });
  });

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  function render(data) {
    $("result-empty").hidden = true;
    $("error").hidden = true;
    $("result").hidden = false;
    const v = $("verdict");
    v.className = "verdict " + data.verdict;
    v.textContent = data.verdict.toUpperCase();
    $("risk").textContent = "Risk " + data.riskScore + "/100";
    const active = data.findings.length;
    $("meta").textContent = active + " finding" + (active === 1 ? "" : "s") + " · " + data.rulesRun + " rules · " + data.durationMs + " ms";
    $("gate").textContent = "Blocks at " + data.gate.failOn + " and above" + (data.aiAuthored ? " (stricter AI-authored policy)." : " (standard policy).");

    const list = $("findings");
    list.replaceChildren();
    if (!active) {
      list.appendChild(el("li", "muted", "No findings. This snippet passes the gate."));
      return;
    }
    for (const f of data.findings) {
      const li = el("li", "finding " + f.severity);
      const head = el("div", "f-head");
      head.append(el("span", "sev " + f.severity, f.severity), el("span", "f-title", f.title), el("span", "f-rule", f.ruleId + " · line " + f.line));
      li.appendChild(head);
      if (f.snippet) li.appendChild(el("pre", "", f.snippet));
      li.appendChild(el("p", "", f.message));
      if (f.remediation) li.appendChild(el("p", "fix", "Fix: " + f.remediation));
      list.appendChild(li);
    }
  }

  $("scan-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("scan-btn");
    btn.disabled = true;
    btn.textContent = "Scanning…";
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ filename: filename.value.trim(), content: code.value, aiAuthored: $("ai").checked }),
      });
      const data = await res.json().catch(() => ({ error: "Unexpected response (" + res.status + ")." }));
      if (!res.ok) throw new Error(data.error || "Scan failed (" + res.status + ").");
      render(data);
    } catch (err) {
      $("result").hidden = true;
      $("result-empty").hidden = true;
      const msg = $("error");
      msg.hidden = false;
      msg.textContent = err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = "Scan";
    }
  });
})();
