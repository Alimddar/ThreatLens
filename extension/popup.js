/**
 * popup.js — ThreatLens SOC Intelligence Dashboard v3
 *
 * Calls /deep-analyze which returns:
 *   ai, hashes, link_scans, whois_info, cert_info, dns_info,
 *   geo_rep, malware_bazaar, urlscan, phishtank, otx
 */

// ─── Config ───────────────────────────────────────────────────────────────────
const SERVER_URL = "http://localhost:8000";

// ─── DOM References ───────────────────────────────────────────────────────────

const btnScan        = document.getElementById("btn-scan");
const btnScanText    = document.getElementById("btn-scan-text");
const btnRefresh     = document.getElementById("btn-refresh");
const scanIcon       = document.getElementById("scan-icon");
const scanSpinner    = document.getElementById("scan-spinner");

const statusDot      = document.getElementById("status-dot");
const statusText     = document.getElementById("status-text");

const senderNameEl   = document.getElementById("sender-name");
const senderEmailEl  = document.getElementById("sender-email");
const senderInitial  = document.getElementById("sender-initial");
const emailSubject   = document.getElementById("email-subject");
const wordCountEl    = document.getElementById("word-count");
const linkCountEl    = document.getElementById("link-count");
const extractTimeEl  = document.getElementById("extract-time");

const resultsSection  = document.getElementById("results-section");
const threatBanner    = document.getElementById("threat-banner");
const threatIcon      = document.getElementById("threat-icon");
const threatLevelTxt  = document.getElementById("threat-level-text");
const threatBadge     = document.getElementById("threat-badge");
const linksSection    = document.getElementById("links-section");
const linksCountBadge = document.getElementById("links-count-badge");
const linksList       = document.getElementById("links-list");
const rawJson         = document.getElementById("raw-json");

const notGmailWarn   = document.getElementById("not-gmail-warning");
const errorCard      = document.getElementById("error-card");
const errorMsgEl     = document.getElementById("error-message");

const aiIdle         = document.getElementById("ai-idle");
const aiLoading      = document.getElementById("ai-loading");
const aiResult       = document.getElementById("ai-result");
const aiError        = document.getElementById("ai-error");
const aiStepVT       = document.getElementById("ai-step-vt");
const aiStepWhois    = document.getElementById("ai-step-whois");
const aiStepFeeds    = document.getElementById("ai-step-feeds");
const aiStepLLM      = document.getElementById("ai-step-llm");
const aiSummaryText  = document.getElementById("ai-summary-text");
const aiFindingsList = document.getElementById("ai-findings-list");
const aiActionText   = document.getElementById("ai-action-text");
const aiConfBadge    = document.getElementById("ai-confidence-badge");

const socSections    = document.getElementById("soc-sections");

// ─── State ────────────────────────────────────────────────────────────────────

let currentTab  = null;
let isLoading   = false;
let lastPayload = null;
let lastScanData = null;   // full deep-analyze response — used for history save

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => { await init(); });

async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;

    if (!tab?.url?.startsWith("https://mail.google.com")) {
      setStatus("inactive", "Not on Gmail");
      notGmailWarn.classList.remove("hidden");
      btnScan.disabled = true;
      return;
    }

    setStatus("active", "Gmail Connected");

    const cached = await getCachedEmailData();
    if (cached) {
      lastPayload = cached;
      renderEmailData(cached);
    }

    // Load history on every open
    await loadAndRenderHistory();

  } catch (err) {
    console.error("[ThreatLens] Init:", err);
    setStatus("error", "Init failed");
  }
}

// ─── Scan Click Handler ───────────────────────────────────────────────────────

btnScan.addEventListener("click",    handleScanClick);
btnRefresh.addEventListener("click", handleScanClick);

async function handleScanClick() {
  if (isLoading) return;
  hideError();
  setAiState("idle");
  socSections.classList.add("hidden");
  setLoadingState(true);

  try {
    // ── Step 1: Extract email ──────────────────────────────────────────────
    const extractResp = await extractEmail();
    if (!extractResp?.success || !extractResp.payload) {
      showError(extractResp?.error || "No email found. Open an email and try again.");
      return;
    }

    lastPayload = extractResp.payload;

    // ── Step 2: Show email metadata immediately ────────────────────────────
    renderEmailData(lastPayload);
    setLoadingState(false);
    setAiState("loading");

    // ── Step 3: Call /deep-analyze ─────────────────────────────────────────
    try {
      setAiStep("vt",    "active");
      await delay(400);
      setAiStep("whois", "active");
      await delay(300);
      setAiStep("feeds", "active");

      const data = await callDeepAnalyze(lastPayload);
      lastScanData = data;

      setAiStep("vt",    "done");
      setAiStep("whois", "done");
      setAiStep("feeds", "done");
      setAiStep("llm",   "active");
      await delay(300);
      setAiStep("llm",   "done");
      await delay(150);

      renderAiResult(data.ai);
      setAiState("result");
      renderThreatBanner(data.ai.threat_level || "SUSPICIOUS");

      if (data.link_scans?.length) applyVTBadgesToLinks(data.link_scans);

      renderSOCSections(data);
      socSections.classList.remove("hidden");

      // Persist to history
      await saveScanToHistory(lastPayload, data);

    } catch (serverErr) {
      console.warn("[ThreatLens] Server error:", serverErr.message);
      showAiError(friendlyServerError(serverErr.message));
      setAiState("error");
    }

  } catch (extractErr) {
    console.error("[ThreatLens] Extraction error:", extractErr);
    setLoadingState(false);

    if (isConnectionError(extractErr)) {
      try {
        await chrome.scripting.executeScript({ target: { tabId: currentTab.id }, files: ["content.js"] });
        await delay(250);
        const retry = await sendMessageToTab(currentTab.id, { type: "EXTRACT_EMAIL" });
        if (retry?.success && retry.payload) {
          lastPayload = retry.payload;
          renderEmailData(lastPayload);
          setAiState("loading");
          callDeepAndRender(lastPayload);
          return;
        }
      } catch (_) {}
      showError("Could not connect to Gmail. Refresh the Gmail tab and try again.");
    } else {
      showError(`Error: ${extractErr.message}`);
    }
  } finally {
    setLoadingState(false);
  }
}

async function callDeepAndRender(payload) {
  try {
    setAiStep("vt",    "active");
    await delay(400);
    setAiStep("whois", "active");
    await delay(300);
    setAiStep("feeds", "active");
    const data = await callDeepAnalyze(payload);
    lastScanData = data;
    setAiStep("vt",    "done");
    setAiStep("whois", "done");
    setAiStep("feeds", "done");
    setAiStep("llm",   "active");
    await delay(300);
    setAiStep("llm",   "done");
    await delay(150);
    renderAiResult(data.ai);
    setAiState("result");
    renderThreatBanner(data.ai?.threat_level || "SUSPICIOUS");
    if (data.link_scans?.length) applyVTBadgesToLinks(data.link_scans);
    renderSOCSections(data);
    socSections.classList.remove("hidden");
    await saveScanToHistory(payload, data);
  } catch (err) {
    showAiError(friendlyServerError(err.message));
    setAiState("error");
  }
}

// ─── Gmail Extraction ─────────────────────────────────────────────────────────

async function extractEmail() {
  return sendMessageToTab(currentTab.id, { type: "EXTRACT_EMAIL" });
}

// ─── Server API Call ──────────────────────────────────────────────────────────

async function callDeepAnalyze(payload) {
  const resp = await fetch(`${SERVER_URL}/deep-analyze`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(payload),
  });

  if (!resp.ok) {
    const detail = await resp.json().then(d => d.detail).catch(() => `HTTP ${resp.status}`);
    throw new Error(detail);
  }

  return resp.json();
}

// ─── Rendering ────────────────────────────────────────────────────────────────

function renderEmailData(payload) {
  if (!payload) return;

  const name  = payload.sender?.name  || "Unknown Sender";
  const email = payload.sender?.email || "";

  senderNameEl.textContent  = name;
  senderEmailEl.textContent = email || "\u00a0";
  senderInitial.textContent = (name !== "Unknown Sender" ? name : email).charAt(0).toUpperCase() || "?";

  emailSubject.textContent = payload.subject || "No Subject";
  wordCountEl.textContent  = payload.wordCount?.toLocaleString() ?? "—";
  linkCountEl.textContent  = payload.linkCount ?? "—";

  if (payload.extractedAt) {
    const d = new Date(payload.extractedAt);
    extractTimeEl.textContent = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  renderThreatBanner(assessThreatLevel(payload));

  if (payload.links?.length > 0) {
    renderLinks(payload.links);
    linksSection.classList.remove("hidden");
  }

  rawJson.textContent = JSON.stringify({
    ...payload,
    body: payload.body?.length > 300
      ? payload.body.substring(0, 300) + `… [${payload.body.length} chars total]`
      : payload.body,
  }, null, 2);

  resultsSection.classList.remove("hidden");
}

// ── AI Result ─────────────────────────────────────────────────────────────────

function renderAiResult(ai) {
  aiSummaryText.textContent = ai?.summary || "";

  aiFindingsList.innerHTML = "";
  (ai?.key_findings || []).forEach((f) => {
    const li = document.createElement("li");
    li.textContent = f;
    aiFindingsList.appendChild(li);
  });

  aiActionText.textContent = ai?.recommended_action || "";

  if (ai?.confidence != null) {
    const pct = Math.round(ai.confidence * 100);
    aiConfBadge.textContent = `${pct}% confidence`;
    aiConfBadge.classList.remove("hidden");
  }
}

// ── SOC Intelligence Sections ─────────────────────────────────────────────────

function renderSOCSections(data) {
  renderIntelSummaryRow(data);
  renderHashes(data.hashes, data.malware_bazaar);
  renderDomainIntel(data.whois_info || [], data.cert_info || [], data.dns_info || []);
  renderIPRep(data.geo_rep || []);
  renderThreatFeeds(data.phishtank || [], data.urlhaus || [], data.threatfox || []);
  renderURLScans(data.urlscan || []);
}

// Summary pill row at the top of SOC sections
function renderIntelSummaryRow(data) {
  const row = document.getElementById("intel-summary-row");
  row.innerHTML = "";

  const pills = [];

  // Domains
  const domainCount = (data.whois_info || []).length;
  if (domainCount > 0) pills.push({ icon: "🌐", label: `${domainCount} Domain${domainCount > 1 ? "s" : ""}`, cls: "neutral" });

  // New domains
  const newDomains = (data.whois_info || []).filter(w => w.is_new).length;
  if (newDomains > 0) pills.push({ icon: "🆕", label: `${newDomains} New Domain`, cls: "warn" });

  // Missing SPF/DMARC
  const missingSpf   = (data.dns_info || []).filter(d => !d.has_spf).length;
  const missingDmarc = (data.dns_info || []).filter(d => !d.has_dmarc).length;
  if (missingSpf   > 0) pills.push({ icon: "📭", label: "No SPF",   cls: "warn" });
  if (missingDmarc > 0) pills.push({ icon: "📭", label: "No DMARC", cls: "warn" });

  // Malicious VT links
  const malLinks = (data.link_scans || []).filter(s => s.is_malicious).length;
  if (malLinks > 0) pills.push({ icon: "🚨", label: `${malLinks} Malicious URL`, cls: "danger" });

  // Phishing confirmed
  const phishing = (data.phishtank || []).filter(p => p.is_phishing).length;
  if (phishing > 0) pills.push({ icon: "🎣", label: "PhishTank Hit", cls: "danger" });

  // ThreatFox hits
  const tfHits = (data.threatfox || []).filter(t => t.hit).length;
  if (tfHits > 0) pills.push({ icon: "🛡️", label: `${tfHits} ThreatFox IOC`, cls: "warn" });

  // URLhaus hits
  const uhHits = (data.urlhaus || []).filter(u => u.is_malicious || u.status === "offline").length;
  if (uhHits > 0) pills.push({ icon: "☣️", label: `${uhHits} URLhaus Hit`, cls: "danger" });

  // MalwareBazaar
  const mbHit = (data.malware_bazaar || []).some(m => m.found);
  if (mbHit) pills.push({ icon: "☠️", label: "MalwareBazaar Hit", cls: "danger" });

  // Proxy/Hosting
  const proxyIPs = (data.geo_rep || []).filter(g => g.is_proxy).length;
  if (proxyIPs > 0) pills.push({ icon: "🔀", label: `${proxyIPs} Proxy/Hosting`, cls: "warn" });

  if (pills.length === 0) {
    pills.push({ icon: "✅", label: "All Checks Clean", cls: "safe" });
  }

  pills.forEach(p => {
    const span = document.createElement("span");
    span.className = `tl-intel-pill tl-intel-pill--${p.cls}`;
    span.textContent = `${p.icon} ${p.label}`;
    row.appendChild(span);
  });
}

function renderHashes(hashes, mbResults) {
  if (!hashes) return;
  document.getElementById("hash-md5").textContent    = hashes.md5    || "—";
  document.getElementById("hash-sha1").textContent   = hashes.sha1   || "—";
  document.getElementById("hash-sha256").textContent = hashes.sha256 || "—";

  const mbHit = (mbResults || []).find(m => m.found);
  if (mbHit) {
    const mbDiv    = document.getElementById("mb-result");
    const mbDetail = document.getElementById("mb-detail");
    mbDiv.classList.remove("hidden");
    const parts = [];
    if (mbHit.file_type)   parts.push(`Type: ${mbHit.file_type}`);
    if (mbHit.threat_name) parts.push(`Threat: ${mbHit.threat_name}`);
    if (mbHit.tags?.length) parts.push(`Tags: ${mbHit.tags.join(", ")}`);
    mbDetail.textContent = parts.join(" | ");
  }
}

function renderDomainIntel(whoisList, certList, dnsList) {
  const container = document.getElementById("domain-intel-list");
  container.innerHTML = "";

  // Build domain-keyed maps
  const certMap  = {};
  certList.forEach(c => { certMap[c.domain] = c; });
  const dnsMap   = {};
  dnsList.forEach(d => { dnsMap[d.domain] = d; });

  if (whoisList.length === 0 && certList.length === 0 && dnsList.length === 0) {
    container.innerHTML = '<p class="tl-intel-empty">No domain data retrieved.</p>';
    return;
  }

  const domains = [...new Set([
    ...whoisList.map(w => w.domain),
    ...certList.map(c => c.domain),
    ...dnsList.map(d => d.domain),
  ])];

  domains.forEach(domain => {
    const w = whoisList.find(w => w.domain === domain);
    const c = certMap[domain];
    const d = dnsMap[domain];

    const block = document.createElement("div");
    block.className = "tl-domain-block";

    const domainHeader = document.createElement("div");
    domainHeader.className = "tl-domain-name";
    domainHeader.textContent = domain;
    block.appendChild(domainHeader);

    const rows = document.createElement("div");
    rows.className = "tl-domain-rows";

    if (w && !w.error) {
      rows.appendChild(makeRow("Registrar", w.registrar || "Unknown"));
      rows.appendChild(makeRow("Age", w.age_days != null ? `${w.age_days} days${w.is_new ? " ⚠️ NEW" : ""}` : "Unknown", w.is_new ? "warn" : ""));
      rows.appendChild(makeRow("Country", w.country || "Unknown"));
      if (w.creation_date) rows.appendChild(makeRow("Created", w.creation_date));
      if (w.expiry_date)   rows.appendChild(makeRow("Expires", w.expiry_date));
    } else if (w?.error) {
      rows.appendChild(makeRow("WHOIS", `Error: ${w.error}`, "muted"));
    }

    if (c && !c.error) {
      rows.appendChild(makeRow("Certificates", `${c.cert_count} found`));
      if (c.oldest_cert) rows.appendChild(makeRow("Oldest Cert", c.oldest_cert));
      if (c.newest_cert) rows.appendChild(makeRow("Newest Cert", c.newest_cert));
      if (c.issuers?.length) rows.appendChild(makeRow("Issuer(s)", c.issuers[0]));
    }

    if (d && !d.error) {
      rows.appendChild(makeRow("SPF",   d.has_spf   ? "✅ Present" : "❌ Missing", d.has_spf   ? "" : "warn"));
      rows.appendChild(makeRow("DMARC", d.has_dmarc ? "✅ Present" : "❌ Missing", d.has_dmarc ? "" : "warn"));
      if (d.mx_records?.length) rows.appendChild(makeRow("MX Records", d.mx_records.join(", ")));
    }

    block.appendChild(rows);
    container.appendChild(block);
  });
}

function renderIPRep(geoList) {
  const container = document.getElementById("ip-rep-list");
  container.innerHTML = "";

  if (geoList.length === 0) {
    container.innerHTML = '<p class="tl-intel-empty">No IP data retrieved.</p>';
    return;
  }

  geoList.forEach(g => {
    if (g.error && !g.ip) {
      const p = document.createElement("p");
      p.className = "tl-intel-empty";
      p.textContent = g.error;
      container.appendChild(p);
      return;
    }

    const block = document.createElement("div");
    block.className = "tl-domain-block";

    const header = document.createElement("div");
    header.className = "tl-domain-name";
    header.textContent = g.ip || "Unknown IP";
    block.appendChild(header);

    const rows = document.createElement("div");
    rows.className = "tl-domain-rows";

    if (g.country) rows.appendChild(makeRow("Location", [g.city, g.country].filter(Boolean).join(", ")));
    if (g.org)     rows.appendChild(makeRow("Org/ISP",  g.org));
    rows.appendChild(makeRow("Proxy/Hosting", g.is_proxy ? "⚠️ Yes" : "✅ No", g.is_proxy ? "warn" : ""));

    if (g.abuse_score != null) {
      const cls = g.abuse_score > 50 ? "danger" : g.abuse_score > 20 ? "warn" : "";
      rows.appendChild(makeRow("Abuse Score", `${g.abuse_score}/100 (${g.abuse_reports || 0} reports)`, cls));
    }

    block.appendChild(rows);
    container.appendChild(block);
  });
}

function renderThreatFeeds(phishList, urlhausList, tfList) {
  const container = document.getElementById("threat-feeds-list");
  container.innerHTML = "";

  let hasData = false;

  // ── PhishTank ──
  phishList.forEach(p => {
    if (p.error) return;
    hasData = true;
    const block = document.createElement("div");
    block.className = "tl-domain-block";

    const header = document.createElement("div");
    header.className = "tl-domain-name";
    header.textContent = "PhishTank";
    block.appendChild(header);

    const rows = document.createElement("div");
    rows.className = "tl-domain-rows";
    rows.appendChild(makeRow("URL",      truncate(p.url, 60)));
    rows.appendChild(makeRow("Phishing", p.is_phishing ? "🎣 CONFIRMED" : "✅ Not found", p.is_phishing ? "danger" : ""));
    if (p.is_phishing && p.verified) rows.appendChild(makeRow("Verified", "Yes"));
    block.appendChild(rows);
    container.appendChild(block);
  });

  // ── URLhaus ──
  urlhausList.forEach(u => {
    if (u.error || u.status === "not_found") return;
    hasData = true;
    const block = document.createElement("div");
    block.className = "tl-domain-block";

    const header = document.createElement("div");
    header.className = "tl-domain-name";
    header.textContent = "URLhaus (abuse.ch)";
    block.appendChild(header);

    const rows = document.createElement("div");
    rows.className = "tl-domain-rows";
    rows.appendChild(makeRow("URL",      truncate(u.url, 60)));
    const statusCls = u.is_malicious ? "danger" : u.status === "offline" ? "warn" : "";
    rows.appendChild(makeRow("Status",   u.status.toUpperCase(), statusCls));
    if (u.threat)      rows.appendChild(makeRow("Threat",     u.threat, "danger"));
    if (u.date_added)  rows.appendChild(makeRow("Reported",   u.date_added));
    if (u.tags?.length) rows.appendChild(makeRow("Tags",      u.tags.join(", ")));
    block.appendChild(rows);
    container.appendChild(block);
  });

  // ── ThreatFox ──
  tfList.forEach(t => {
    if (t.error || !t.hit) return;
    hasData = true;
    const block = document.createElement("div");
    block.className = "tl-domain-block";

    const header = document.createElement("div");
    header.className = "tl-domain-name";
    header.textContent = `ThreatFox: ${t.indicator}`;
    block.appendChild(header);

    const rows = document.createElement("div");
    rows.className = "tl-domain-rows";
    if (t.malware)    rows.appendChild(makeRow("Malware",    t.malware, "danger"));
    if (t.confidence != null) rows.appendChild(makeRow("Confidence", `${t.confidence}%`, t.confidence > 50 ? "danger" : "warn"));
    if (t.first_seen) rows.appendChild(makeRow("First seen", t.first_seen));
    if (t.tags?.length) rows.appendChild(makeRow("Tags",     t.tags.join(", ")));
    block.appendChild(rows);
    container.appendChild(block);
  });

  if (!hasData) {
    container.innerHTML = '<p class="tl-intel-empty">No threat feed hits — all checked with URLhaus, ThreatFox &amp; PhishTank.</p>';
  }
}

function renderURLScans(urlscanList) {
  const container = document.getElementById("urlscan-list");
  container.innerHTML = "";

  const submitted = urlscanList.filter(u => u.status === "submitted" || u.result_url);

  if (submitted.length === 0) {
    const noKey = urlscanList.some(u => u.status === "no_key");
    container.innerHTML = `<p class="tl-intel-empty">${
      noKey ? "Add URLSCAN_API_KEY to server/.env to enable URL scanning." : "No scans submitted."
    }</p>`;
    return;
  }

  submitted.forEach(u => {
    const block = document.createElement("div");
    block.className = "tl-domain-block";

    const rows = document.createElement("div");
    rows.className = "tl-domain-rows";

    rows.appendChild(makeRow("URL", truncate(u.url, 60)));
    rows.appendChild(makeRow("Status", "Submitted — scan in progress"));

    if (u.result_url) {
      const link = document.createElement("a");
      link.href      = u.result_url;
      link.target    = "_blank";
      link.className = "tl-intel-link";
      link.textContent = "View Report →";
      rows.appendChild(link);
    }

    block.appendChild(rows);
    container.appendChild(block);
  });
}

// ── VT Badges ─────────────────────────────────────────────────────────────────

function applyVTBadgesToLinks(linkScans) {
  const scanMap = new Map(linkScans.map(s => [s.url, s]));

  linksList.querySelectorAll("li[data-url]").forEach((li) => {
    const url  = li.dataset.url;
    const scan = scanMap.get(url);
    if (!scan) return;

    li.querySelector(".tl-vt-badge")?.remove();
    const badge = document.createElement("span");
    badge.className = "tl-vt-badge";

    if (scan.is_malicious) {
      badge.className += " tl-vt-badge--malicious";
      badge.textContent = `⚠ ${scan.malicious}/${scan.total}`;
    } else if (scan.is_suspicious) {
      badge.className += " tl-vt-badge--suspicious";
      badge.textContent = `? ${scan.suspicious}/${scan.total}`;
    } else if (scan.status === "first_scan") {
      badge.className += " tl-vt-badge--unknown";
      badge.textContent = "NEW";
    } else if (scan.status === "ok") {
      badge.className += " tl-vt-badge--clean";
      badge.textContent = "CLEAN";
    } else {
      return;
    }

    li.appendChild(badge);
  });
}

// ── Threat Banner ─────────────────────────────────────────────────────────────

function renderThreatBanner(level) {
  threatBanner.classList.remove(
    "tl-threat-banner--safe", "tl-threat-banner--suspicious", "tl-threat-banner--malicious"
  );
  threatBadge.classList.remove(
    "tl-threat-badge--safe", "tl-threat-badge--suspicious", "tl-threat-badge--malicious"
  );

  const cfg = {
    SAFE:       { banner: "tl-threat-banner--safe",      badge: "tl-threat-badge--safe",      icon: "🛡️", label: "No Threats Detected" },
    SUSPICIOUS: { banner: "tl-threat-banner--suspicious", badge: "tl-threat-badge--suspicious", icon: "⚠️", label: "Suspicious Signals Found" },
    MALICIOUS:  { banner: "tl-threat-banner--malicious",  badge: "tl-threat-badge--malicious",  icon: "🚨", label: "Potential Threat Detected" },
  };

  const c = cfg[level] || cfg.SAFE;
  threatBanner.classList.add(c.banner);
  threatBadge.classList.add(c.badge);
  threatIcon.textContent     = c.icon;
  threatLevelTxt.textContent = c.label;
  threatBadge.textContent    = level;
}

// ── Links List ────────────────────────────────────────────────────────────────

function renderLinks(links) {
  linksCountBadge.textContent = links.length;
  linksList.innerHTML = "";

  links.forEach((href) => {
    const suspicious = looksLikeSuspiciousUrl(href);
    const li = document.createElement("li");
    li.className   = "tl-link-item";
    li.dataset.url = href;

    li.innerHTML = `
      <svg class="${suspicious ? "suspect" : "normal"}" xmlns="http://www.w3.org/2000/svg"
           viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
      <span class="tl-link-url ${suspicious ? "suspect" : "normal"}" title="${escapeHtml(href)}">${escapeHtml(href)}</span>
    `;
    linksList.appendChild(li);
  });
}

// ─── Heuristic ────────────────────────────────────────────────────────────────

function assessThreatLevel(payload) {
  const { links = [], body = "" } = payload;
  if (links.some(u => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u))) return "MALICIOUS";
  const suspTLDs = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".ru"];
  const hasSuspTLD = links.some(u => suspTLDs.some(t => u.toLowerCase().includes(t)));
  const urgency    = ["verify your account", "click here immediately", "your account will be suspended",
                      "unusual sign-in activity", "confirm your identity", "update your payment",
                      "limited time", "act now", "urgent action required"];
  const hasUrgency = urgency.some(p => body.toLowerCase().includes(p));
  if (hasSuspTLD || hasUrgency || links.length > 5) return "SUSPICIOUS";
  return "SAFE";
}

function looksLikeSuspiciousUrl(url) {
  return [/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, /\.(xyz|top|tk|ml|ga|cf|gq|pw|cc|ru)\//i,
          /[a-z0-9-]{30,}\./, /bit\.ly|tinyurl\.com|t\.co|ow\.ly/i].some(p => p.test(url));
}

// ─── AI Card State Machine ────────────────────────────────────────────────────

function setAiState(state) {
  aiIdle.classList.add("hidden");
  aiLoading.classList.add("hidden");
  aiResult.classList.add("hidden");
  aiError.classList.add("hidden");
  aiConfBadge.classList.add("hidden");

  if (state === "idle")    aiIdle.classList.remove("hidden");
  if (state === "loading") {
    aiLoading.classList.remove("hidden");
    [aiStepVT, aiStepWhois, aiStepFeeds, aiStepLLM].forEach(el => el.className = "tl-ai-step");
  }
  if (state === "result")  aiResult.classList.remove("hidden");
  if (state === "error")   aiError.classList.remove("hidden");
}

function setAiStep(step, state) {
  const map = { vt: aiStepVT, whois: aiStepWhois, feeds: aiStepFeeds, llm: aiStepLLM };
  const el  = map[step];
  if (el) el.className = "tl-ai-step" + (state !== "idle" ? ` ${state}` : "");
}

function showAiError(msg) {
  document.getElementById("ai-error-text").textContent = msg;
}

// ─── UI Helpers ───────────────────────────────────────────────────────────────

function setLoadingState(loading) {
  isLoading = loading;
  btnScan.disabled = loading;
  if (loading) {
    scanIcon.classList.add("hidden");
    scanSpinner.classList.remove("hidden");
    btnScanText.textContent = "Extracting…";
  } else {
    scanIcon.classList.remove("hidden");
    scanSpinner.classList.add("hidden");
    btnScanText.textContent = "Deep Scan Email";
  }
}

function setStatus(state, label) {
  statusDot.className    = "status-dot status-dot--" + state;
  statusText.textContent = label;
}

function showError(msg) {
  errorMsgEl.textContent = msg;
  errorCard.classList.remove("hidden");
}

function hideError() {
  errorCard.classList.add("hidden");
  errorMsgEl.textContent = "";
}

// ─── DOM Helpers ──────────────────────────────────────────────────────────────

function makeRow(label, value, cls = "") {
  const row = document.createElement("div");
  row.className = "tl-kv-row" + (cls ? ` tl-kv-row--${cls}` : "");

  const k = document.createElement("span");
  k.className   = "tl-kv-key";
  k.textContent = label;

  const v = document.createElement("span");
  v.className   = "tl-kv-val";
  v.textContent = value || "—";

  row.appendChild(k);
  row.appendChild(v);
  return row;
}

function truncate(str, max) {
  if (!str) return "";
  return str.length > max ? str.substring(0, max) + "…" : str;
}

// ─── Scan History ─────────────────────────────────────────────────────────────

/**
 * Builds a compact history entry from a completed scan.
 * Stores only what's needed for the history list — no raw body, no full scan data.
 */
function buildHistoryEntry(payload, deepData) {
  const maliciousLinks = (deepData.link_scans || []).filter(s => s.is_malicious).length;
  const suspiciousLinks = (deepData.link_scans || []).filter(s => s.is_suspicious).length;
  return {
    id:           Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    timestamp:    new Date().toISOString(),
    sender:       { name: payload.sender?.name || "", email: payload.sender?.email || "" },
    subject:      payload.subject || "No Subject",
    threat_level: deepData.ai?.threat_level || "SUSPICIOUS",
    confidence:   deepData.ai?.confidence   || 0,
    summary:      deepData.ai?.summary      || "",
    key_findings: (deepData.ai?.key_findings || []).slice(0, 3),
    recommended_action: deepData.ai?.recommended_action || "",
    sha256:       deepData.hashes?.sha256   || "",
    link_count:   payload.linkCount         || 0,
    malicious_links:  maliciousLinks,
    suspicious_links: suspiciousLinks,
  };
}

async function saveScanToHistory(payload, deepData) {
  const entry = buildHistoryEntry(payload, deepData);
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "SAVE_SCAN", entry }, () => {
      if (chrome.runtime.lastError) { resolve(); return; }
      loadAndRenderHistory();   // refresh the panel in place
      resolve();
    });
  });
}

async function loadAndRenderHistory() {
  const history = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_HISTORY" }, (res) => {
      if (chrome.runtime.lastError) { resolve([]); return; }
      resolve(res?.history || []);
    });
  });
  renderHistory(history);
}

function renderHistory(history) {
  const list        = document.getElementById("history-list");
  const countBadge  = document.getElementById("history-count-badge");
  const clearBtn    = document.getElementById("btn-clear-history");

  if (!history.length) {
    list.innerHTML = '<p class="tl-intel-empty">No scans yet — run your first deep scan.</p>';
    countBadge.classList.add("hidden");
    clearBtn.classList.add("hidden");
    return;
  }

  countBadge.textContent = history.length;
  countBadge.classList.remove("hidden");
  clearBtn.classList.remove("hidden");

  list.innerHTML = "";
  history.forEach(entry => {
    const item = document.createElement("div");
    item.className = "tl-history-item";

    const levelCls = {
      SAFE:       "safe",
      SUSPICIOUS: "warn",
      MALICIOUS:  "danger",
    }[entry.threat_level] || "warn";

    const dateStr = new Date(entry.timestamp).toLocaleString([], {
      month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });

    item.innerHTML = `
      <div class="tl-history-item-header">
        <span class="tl-history-badge tl-history-badge--${levelCls}">${entry.threat_level}</span>
        <span class="tl-history-time">${dateStr}</span>
      </div>
      <div class="tl-history-subject">${escapeHtml(truncate(entry.subject, 55))}</div>
      <div class="tl-history-meta">
        <span class="tl-history-sender">${escapeHtml(truncate(entry.sender.email || entry.sender.name, 40))}</span>
        ${entry.malicious_links > 0
          ? `<span class="tl-history-meta-pill tl-history-meta-pill--danger">${entry.malicious_links} malicious</span>`
          : ""}
        ${entry.suspicious_links > 0 && entry.malicious_links === 0
          ? `<span class="tl-history-meta-pill tl-history-meta-pill--warn">${entry.suspicious_links} suspicious</span>`
          : ""}
        ${entry.link_count > 0
          ? `<span class="tl-history-meta-pill">${entry.link_count} links</span>`
          : ""}
      </div>
      ${entry.summary
        ? `<div class="tl-history-summary-text">${escapeHtml(entry.summary)}</div>`
        : ""}
      ${entry.sha256
        ? `<div class="tl-history-hash">SHA-256: <code>${entry.sha256}</code></div>`
        : ""}
    `;
    list.appendChild(item);
  });
}

// Clear history button
document.getElementById("btn-clear-history")?.addEventListener("click", async (e) => {
  e.stopPropagation();   // don't toggle the <details>
  chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => {
    renderHistory([]);
  });
});

// ─── Chrome API Helpers ───────────────────────────────────────────────────────

function sendMessageToTab(tabId, message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (res) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(res);
    });
  });
}

function getCachedEmailData() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_EMAIL_DATA" }, (res) => {
      if (chrome.runtime.lastError) resolve(null);
      else resolve(res?.payload || null);
    });
  });
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  const d = document.createElement("div");
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

function isConnectionError(err) {
  return err.message?.includes("Could not establish connection")
      || err.message?.includes("Receiving end does not exist");
}

function friendlyServerError(msg) {
  if (msg?.includes("fetch") || msg?.includes("NetworkError") || msg?.includes("Failed to fetch")) {
    return "Backend server is not running. In terminal: cd server && uvicorn main:app --reload";
  }
  if (msg?.includes("ANTHROPIC_API_KEY")) return "ANTHROPIC_API_KEY missing from server/.env.";
  if (msg?.includes("VIRUS_TOTAL"))       return "VIRUS_TOTAL_API_KEY missing from server/.env.";
  return msg || "Server error. Check terminal for details.";
}
