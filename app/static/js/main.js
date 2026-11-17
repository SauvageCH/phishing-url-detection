// Front-end logic: call the API, render the verdict, the URL anatomy and the warnings.
const $ = (id) => document.getElementById(id);
const form = $("form"), input = $("url"), button = $("go");
const history = [];

function setError(msg) {
  $("error").textContent = msg || "";
  $("error").hidden = !msg;
}

// Build the URL as segments so risky parts can be underlined.
function renderAnatomy(data) {
  const p = data.parts;
  const level = {}; // part name -> highest severity
  data.red_flags.forEach((f) => {
    level[f.part] = Math.max(level[f.part] || 0, f.severity);
  });
  const hostLevel = level.host || 0;

  const seg = (text, cls, lvl) => {
    if (!text) return null;
    const s = document.createElement("span");
    s.className = "seg " + cls + (lvl ? " flag" + lvl : "");
    s.textContent = text;
    return s;
  };

  const nodes = [
    seg(p.scheme + "://", "muted", level.scheme),
    p.subdomain ? seg(p.subdomain + ".", "", Math.max(level.subdomain || 0, hostLevel)) : null,
    seg(p.domain, "domain", Math.max(level.domain || 0, hostLevel)),
    p.suffix ? seg("." + p.suffix, "", Math.max(level.suffix || 0, hostLevel)) : null,
    seg(p.path, "muted", level.path),
    p.query ? seg("?" + p.query, "muted", level.path) : null,
  ].filter(Boolean);

  $("anatomy").replaceChildren(...nodes);
}

function renderFlags(flags) {
  const ul = $("flags");
  ul.replaceChildren();
  if (!flags.length) {
    const li = document.createElement("li");
    li.className = "none";
    li.textContent = "No suspicious pattern found in the address.";
    ul.appendChild(li);
    return;
  }
  flags.forEach((f) => {
    const li = document.createElement("li");
    li.className = "s" + f.severity;
    li.textContent = f.message;
    ul.appendChild(li);
  });
}

function renderHistory() {
  $("history-wrap").hidden = history.length === 0;
  const ul = $("history");
  ul.replaceChildren();
  history.slice(0, 8).forEach((h) => {
    const li = document.createElement("li");
    const u = document.createElement("span");
    u.className = "u";
    u.textContent = h.url;
    const pct = document.createElement("span");
    pct.className = "pct " + h.risk;
    pct.textContent = Math.round(h.p * 100) + "%";
    li.append(u, pct);
    ul.appendChild(li);
  });
}

function render(data) {
  const pct = Math.round(data.probability_phishing * 100);
  const titles = {
    low: ["Looks legitimate", "Nothing in this address resembles known phishing patterns."],
    medium: ["Suspicious", "Some signs are worrying. Check carefully before you click or sign in."],
    high: ["Likely phishing", "This address matches several phishing patterns. Do not enter any data."],
  };
  const [title, sub] = titles[data.risk_level];
  $("result").dataset.risk = data.risk_level;
  $("verdict-title").textContent = title;
  $("verdict-sub").textContent = sub;
  $("meter-value").textContent = pct + "% phishing score";
  $("meter-fill").style.left = `calc(${pct}% - 2px)`;
  renderAnatomy(data);
  renderFlags(data.red_flags);
  $("result").hidden = false;

  history.unshift({ url: data.url, p: data.probability_phishing, risk: data.risk_level });
  renderHistory();
}

async function analyze(url) {
  setError("");
  button.disabled = true;
  button.textContent = "Analyzing…";
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Something went wrong.");
    render(data);
  } catch (err) {
    $("result").hidden = true;
    setError(err.message);
  } finally {
    button.disabled = false;
    button.textContent = "Analyze URL";
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  analyze(input.value);
});

document.querySelectorAll(".chip").forEach((chip) =>
  chip.addEventListener("click", () => {
    input.value = chip.dataset.url;
    analyze(chip.dataset.url);
  })
);
