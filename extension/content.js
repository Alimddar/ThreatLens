/**
 * content.js — ThreatLens Gmail Email Scraper
 *
 * Injected into every https://mail.google.com/* page.
 * Also injected programmatically by popup.js when Gmail was already open
 * before the extension was installed — the guard below prevents double-loading.
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │  GMAIL DOM SELECTOR NOTES (verified 2025)                            │
 * │                                                                      │
 * │  Gmail is a React SPA with obfuscated class names. The selectors     │
 * │  below use the most stable attributes (data attrs, ARIA roles, and   │
 * │  the handful of semantic class names Google has kept constant).      │
 * │                                                                      │
 * │  UPDATE THESE if Gmail changes its DOM:                              │
 * │  ────────────────────────────────────────────────────────────────    │
 * │  Sender name  : span.gD  → textContent                              │
 * │  Sender email : span.gD  → "email" attribute (non-standard but      │
 * │                            long-standing; also try data-hovercard-id)│
 * │  Subject      : h2.hP   (primary)  /  .ha h2  (fallback)           │
 * │  Body         : div.a3s.aiL  (primary)  /  div.a3s  /  div.ii.gt   │
 * │  Links        : a[href] inside the body element                      │
 * └──────────────────────────────────────────────────────────────────────┘
 */

// ─── Double-load guard ────────────────────────────────────────────────────────
// popup.js may call chrome.scripting.executeScript() to inject this file when
// Gmail was already open (content_scripts declaration only fires on page load).
// Without this guard, the message listener would be registered twice, causing
// duplicate responses and a "const redeclaration" crash on the second injection.

if (!window.__threatLensContentLoaded) {
  window.__threatLensContentLoaded = true;

// ─── Constants ────────────────────────────────────────────────────────────────

// Google-internal link patterns — excluded from the threat-relevant links list.
const EXCLUDED_LINK_PATTERNS = [
  "google.com/intl",
  "accounts.google.com",
  "support.google.com",
  "mail.google.com",
  "mailto:",
];

// ─── Selector Lists ───────────────────────────────────────────────────────────
// Each array is tried in order; the first match wins.
// Add new selectors at the TOP when Gmail updates (keeps the most recent first).

const SENDER_SELECTORS = [
  "span.gD",                     // Primary: long-standing Gmail sender span
  "span[email]",                 // Any span with an "email" attribute
  "[data-hovercard-id*='@']",    // Elements with email address in hovercard id
  ".cf .go",                     // Sender name in some thread layouts
  ".gE.iv.gt span",              // Another from-field wrapper variant
];

const SUBJECT_SELECTORS = [
  "h2.hP",                        // Primary: subject heading (very stable)
  ".ha h2",                       // Subject inside thread header area
  ".hP",                          // Class alone without tag constraint
  "[data-thread-id] h2",          // Generic thread container
  "table.cf h2",                  // Older print/compose view fallback
];

const BODY_SELECTORS = [
  "div.a3s.aiL",                  // Primary: sanitized rendered body (most stable)
  "div.a3s",                      // Without aiL in case class changes
  "div.ii.gt > div",              // Fallback: child of the message wrapper
  "div.ii.gt",                    // The wrapper itself if no child found
  "div.gs > div.am",              // Compact view email body
];

// ─── Main Extraction Function ─────────────────────────────────────────────────

/**
 * extractEmailData()
 * Scrapes the active Gmail email thread from the DOM.
 *
 * Returns a structured payload or null if no email is open / no content found.
 * NOTE: Returns null ONLY for the no-email case. Partial data (e.g., no body)
 * still returns a payload so the user at least sees sender + subject.
 *
 * @returns {Object|null}
 */
function extractEmailData() {

  // ── Guard: confirm Gmail has rendered its main view ──────────────────────
  const mainView = document.querySelector('div[role="main"]')
                || document.querySelector('[jscontroller] [role="main"]')
                || document.querySelector(".AO");  // Gmail main column class

  if (!mainView) {
    console.warn("[ThreatLens] Could not find Gmail main view. Is the page loaded?");
    return null;
  }

  // ── 1. Sender Name + Email ────────────────────────────────────────────────
  let senderName  = "Unknown Sender";
  let senderEmail = "";

  for (const selector of SENDER_SELECTORS) {
    const candidates = document.querySelectorAll(selector);
    if (candidates.length === 0) continue;

    // Use the LAST match — in a thread the last one is the most recent message.
    const el = candidates[candidates.length - 1];

    const name = el.textContent?.trim();
    if (name) senderName = name;

    // Gmail stores the email address in the "email" attribute of span.gD —
    // this has existed since at least 2015 and is still present in 2025.
    const email = el.getAttribute("email")
               || el.getAttribute("data-hovercard-id")
               || extractEmailFromText(el.getAttribute("title") || "");

    if (email && email.includes("@")) {
      senderEmail = email;
    }

    // Stop trying selectors once we have at least a name.
    if (senderName !== "Unknown Sender") break;
  }

  // ── 2. Subject Line ───────────────────────────────────────────────────────
  let subject = "No Subject";

  for (const selector of SUBJECT_SELECTORS) {
    const el = document.querySelector(selector);
    if (el?.textContent?.trim()) {
      subject = el.textContent.trim();
      break;
    }
  }

  // ── 3. Email Body Text ────────────────────────────────────────────────────
  let bodyText    = "";
  let bodyElement = null;

  for (const selector of BODY_SELECTORS) {
    const candidates = document.querySelectorAll(selector);
    if (candidates.length > 0) {
      // Last element in a thread = latest expanded message.
      bodyElement = candidates[candidates.length - 1];
      break;
    }
  }

  if (bodyElement) {
    // innerText preserves whitespace structure and strips HTML tags automatically.
    bodyText = (bodyElement.innerText || "")
      .replace(/\n{3,}/g, "\n\n")  // Collapse 3+ blank lines to 2
      .trim();
  }

  if (!bodyText) {
    console.warn("[ThreatLens] Email body not found. Gmail DOM may have changed. " +
                 "Try updating the BODY_SELECTORS array in content.js.");
    bodyText = "[Body extraction failed — see console for details]";
  }

  // ── 4. Embedded Links ─────────────────────────────────────────────────────
  // Scope to body element for precision; fall back to full main view.
  const linkScope = bodyElement || mainView;
  const extractedLinks = [];

  linkScope.querySelectorAll("a[href]").forEach((a) => {
    const href = a.href; // Browser resolves relative URLs automatically.
    if (!href) return;

    const excluded = EXCLUDED_LINK_PATTERNS.some(p => href.includes(p))
                  || href.startsWith("javascript:")
                  || href === "#"
                  || extractedLinks.includes(href);

    if (!excluded) extractedLinks.push(href);
  });

  // ── 5. Package payload ────────────────────────────────────────────────────
  const payload = {
    extractedAt: new Date().toISOString(),
    sender: {
      name:  senderName,
      email: senderEmail || "unknown",
    },
    subject,
    body:      bodyText,
    links:     extractedLinks,
    linkCount: extractedLinks.length,
    wordCount: bodyText.split(/\s+/).filter(Boolean).length,
  };

  console.log("[ThreatLens] Payload extracted:", payload);
  return payload;
}

// ─── Helper: Parse Email Address from Text ────────────────────────────────────

function extractEmailFromText(str) {
  if (!str) return null;
  // "Name <email@example.com>"
  const bracket = str.match(/<([^>]+@[^>]+)>/);
  if (bracket) return bracket[1].trim();
  // Bare "email@example.com"
  const bare = str.match(/[\w.+\-]+@[\w\-]+\.[a-z]{2,}/i);
  if (bare) return bare[0].trim();
  return null;
}

// ─── Message Listener ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type !== "EXTRACT_EMAIL") return;

  console.log("[ThreatLens] EXTRACT_EMAIL received.");

  const payload = extractEmailData();

  if (payload) {
    // Respond immediately — the response channel is sync-safe.
    sendResponse({ success: true, payload });

    // Cache in background service worker for popup re-opens (fire-and-forget).
    chrome.runtime.sendMessage({ type: "EMAIL_DATA", payload }, () => {
      if (chrome.runtime.lastError) {
        // Service worker may have been idle-terminated — non-fatal.
        console.warn("[ThreatLens] Cache write skipped:", chrome.runtime.lastError.message);
      }
    });

  } else {
    sendResponse({
      success: false,
      error: "No email is open. Please click on an email to open it, then click Analyze Email.",
    });
  }

  // Return true keeps the channel open for the synchronous sendResponse above
  // (required by Chrome's async messaging contract even when called synchronously).
  return true;
});

// ─── Ready ────────────────────────────────────────────────────────────────────

console.log("[ThreatLens] Content script ready on Gmail.");

} // end double-load guard
