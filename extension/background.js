/**
 * background.js — ThreatLens Service Worker (Manifest V3) v3
 *
 * Responsibilities:
 *  1. Cache the most-recently extracted email in chrome.storage.local
 *     (persists across popup open/close).
 *  2. Maintain a scan history of the last MAX_HISTORY results so the user
 *     can review past findings after the popup is reopened.
 *  3. Act as message broker between content.js ↔ popup.js.
 *
 * Storage layout in chrome.storage.local:
 *   threatLensEmailData  — latest extracted payload (EmailPayload shape)
 *   threatLensHistory    — array of HistoryEntry, newest-first, capped at MAX_HISTORY
 */

const MAX_HISTORY = 25;

// ─── Message Router ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {

  // ── EMAIL_DATA ─────────────────────────────────────────────────────────────
  // content.js scraped a Gmail message → cache it so popup can retrieve on load.
  if (message.type === "EMAIL_DATA") {
    chrome.storage.local.set({ threatLensEmailData: message.payload }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  // ── GET_EMAIL_DATA ──────────────────────────────────────────────────────────
  // Popup asks for the cached email payload.
  if (message.type === "GET_EMAIL_DATA") {
    chrome.storage.local.get("threatLensEmailData", (result) => {
      sendResponse({ payload: result.threatLensEmailData || null });
    });
    return true;
  }

  // ── CLEAR_EMAIL_DATA ────────────────────────────────────────────────────────
  // Popup explicitly clears the current scan (does NOT affect history).
  if (message.type === "CLEAR_EMAIL_DATA") {
    chrome.storage.local.remove("threatLensEmailData", () => {
      sendResponse({ success: true });
    });
    return true;
  }

  // ── SAVE_SCAN ───────────────────────────────────────────────────────────────
  // Popup sends a completed scan result to be stored in history.
  // message.entry  — HistoryEntry object to prepend
  if (message.type === "SAVE_SCAN") {
    chrome.storage.local.get("threatLensHistory", (result) => {
      const history = result.threatLensHistory || [];
      // Prepend newest entry; evict oldest if over cap
      history.unshift(message.entry);
      if (history.length > MAX_HISTORY) history.splice(MAX_HISTORY);
      chrome.storage.local.set({ threatLensHistory: history }, () => {
        sendResponse({ success: true, count: history.length });
      });
    });
    return true;
  }

  // ── GET_HISTORY ─────────────────────────────────────────────────────────────
  // Popup requests the full scan history list.
  if (message.type === "GET_HISTORY") {
    chrome.storage.local.get("threatLensHistory", (result) => {
      sendResponse({ history: result.threatLensHistory || [] });
    });
    return true;
  }

  // ── CLEAR_HISTORY ───────────────────────────────────────────────────────────
  // User explicitly clears all history from the popup.
  if (message.type === "CLEAR_HISTORY") {
    chrome.storage.local.remove("threatLensHistory", () => {
      sendResponse({ success: true });
    });
    return true;
  }
});

// ─── Install / Update ─────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    console.log("[ThreatLens] Installed. Storage initialised.");
  } else if (details.reason === "update") {
    console.log(`[ThreatLens] Updated to v${chrome.runtime.getManifest().version}.`);
  }
});
