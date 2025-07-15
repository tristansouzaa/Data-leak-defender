// detector.js – runs as content script (has chrome.*)
(function() {
  // ALL YOUR fetch, XHR, beacon logic
  window.forceLeakPopup = () => showAlertPopup("ssn", "debug.test");
})();

console.log("[DLD] detector.js is running in page context!");
// Respond to requests for enabled patterns from inject.js
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const msg = event.data;

  if (msg?.type === "GET_ENABLED_PATTERNS") {
    chrome.storage.local.get("enabledPatterns", ({ enabledPatterns }) => {
      window.postMessage({
        type: "ENABLED_PATTERNS_RESULT",
        enabledPatterns: enabledPatterns || []
      }, "*");
    });
  }
});

// Inject inject.js into page context
const script = document.createElement("script");
script.src = chrome.runtime.getURL("inject.js");
(document.documentElement || document.head).appendChild(script);
script.remove();
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "REFRESH_PATTERNS") {
    chrome.storage.local.get("enabledPatterns", ({ enabledPatterns = [] }) => {
      window.postMessage({
        type: "ENABLED_PATTERNS_RESULT",
        enabledPatterns
      }, "*");
    });
  }
});
