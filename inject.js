console.log("[DLD] inject.js with smart detection loaded");

const FRIENDLY_LABELS = {
  ssn: "Social Security Number",
  credit_card: "Credit Card Number",
  cvv: "CVV Code",
  phone: "Phone Number",
  email: "Email Address",
  gps: "GPS Coordinates",
  aba: "ABA Routing Number",
  swift: "SWIFT/BIC Code",
  passport_us: "US Passport Number",
  iban: "IBAN",
  vin: "Vehicle VIN",
  dl_us: "Driver's License",
  dob: "Date of Birth",
  place_of_birth: "Place of Birth",
  employment: "Employment Info",
  user_password: "User Password",
};

const CONTEXT_KEYWORDS = {
  ssn: ["ssn", "social", "security"],
  credit_card: ["cc", "credit", "card", "visa", "master", "amex"],
  cvv: ["cvv", "cvc", "security", "card"],
  phone: ["phone", "mobile", "contact", "tel", "cell"],
  email: ["email", "e-mail", "mail", "contact"],
  gps: ["lat", "lon", "gps", "geo", "coordinates"],
  aba: ["aba", "routing", "bank"],
  swift: ["swift", "bic", "bank"],
  passport_us: ["passport", "travel", "document"],
  iban: ["iban", "account", "bank"],
  vin: ["vin", "vehicle", "car"],
  dl_us: ["driver", "license", "dl", "permit"],
  dob: ["dob", "birth", "birthday", "born"],
  place_of_birth: ["place", "birth", "pob", "born"],
  employment: ["employer", "job", "work", "position", "company"],
  home_address: ["address", "home", "street", "residence"],
};

const PATTERN_IDS = {
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  passport_us: /\b[A-Z]{2}\d{7}\b/,
  iban: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b/,
  cvv: /\b\d{3,4}\b/,
  vin: /\b[A-HJ-NPR-Z0-9]{17}\b/,
  dl_us: /\b[A-Z0-9]{5,15}\b/,
  home_address: /\d{1,5}\s\w+\s\w+/,
  gps: /\b[-+]?\d{1,2}\.\d+,\s*[-+]?\d{1,3}\.\d+\b/,
  dob: /\b\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}\b/,
  place_of_birth: /\bPlace\s+of\s+Birth:?\s*[A-Za-z\s]+\b/i,
  employment: /\b(?:Employer|Company|Position)?:?\s[A-Za-z0-9 &]+\b/i,
  email: /[\w.-]+@[\w.-]+\.[A-Za-z]{2,6}/,
  phone: /\b\+?\d[\d\s.-]{7,}\b/,
  credit_card: /\b(?:\d[ -]*?){13,16}\b/,
  aba: /\b\d{9}\b/,
  swift: /\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b/i,
};

let userPasswords = [];
let enabledIDs = new Set(Object.keys(PATTERN_IDS));

const whitelistedDomains = ["x.com"];
const isWhitelisted = (host) => {
  const cleanHost = host.toLowerCase().replace(/^www\./, '');
  return whitelistedDomains.some(domain => {
    const cleanDomain = domain.toLowerCase();
    return cleanHost === cleanDomain || cleanHost.endsWith('.' + cleanDomain);
  });
};

const allow = new Set(JSON.parse(localStorage.getItem("__dld_allow__") || "[]"));
const block = new Set(JSON.parse(localStorage.getItem("__dld_block__") || "[]"));
const set = (k, arr) => localStorage.setItem(k, JSON.stringify(arr));
const hname = (u) => { try { return new URL(u, location.href).hostname; } catch { return "Unknown"; } };
const third = (u) => hname(u) !== location.hostname;

function contextSuggests(key, id) {
  if (!key || !id || !CONTEXT_KEYWORDS[id]) return false;
  return CONTEXT_KEYWORDS[id].some(hint => key.toLowerCase().includes(hint));
}

function detect(objOrString) {
  if (!objOrString) return null;
  const raw = typeof objOrString === "string" ? objOrString : JSON.stringify(objOrString);
  const text = raw.toLowerCase();

  if (typeof objOrString === "object" && objOrString !== null) {
    for (const [key, val] of Object.entries(objOrString)) {
      const valStr = String(val);
      if (valStr.length > 60 || valStr.length < 3) continue;
      
      for (const id of enabledIDs) {
        const rx = PATTERN_IDS[id];
        if (!rx) continue;
        
        if (rx.test(valStr) && contextSuggests(key, id)) {
          return id;
        }
      }
    }
  }

  for (const id of enabledIDs) {
    const rx = PATTERN_IDS[id];
    if (!rx) continue;

    if (rx.test(text)) {
      const keywords = CONTEXT_KEYWORDS[id] || [];
      const hasContext = keywords.some(keyword => text.includes(keyword));
      
      if (!hasContext) continue;
      
      if (id === "cvv" && !/\b(cvv|cvc|security|card)[^\w]{0,8}\d{3,4}\b/i.test(text)) continue;
      if (id === "ssn" && !/\b(ssn|social|security)[^\w]{0,8}\d{3}-\d{2}-\d{4}\b/i.test(text)) continue;
      if (id === "dl_us" && !/\b(driver|license|dl|permit)[^\w]{0,8}[A-Z0-9]{5,15}\b/i.test(text)) continue;
      if (id === "credit_card" && !/\b(card|credit|cc|visa|master|amex)[^\w]{0,8}[\d\s-]{13,19}\b/i.test(text)) continue;
      if (id === "phone" && !/\b(phone|tel|mobile|cell|contact)[^\w]{0,8}[\d\s.+()-]{7,}\b/i.test(text)) continue;
      if (id === "email" && !/\b(email|e-mail|mail|contact)[^\w]{0,8}[\w.-]+@[\w.-]+\.[a-z]{2,}\b/i.test(text)) continue;
      if (id === "aba" && !/\b(aba|routing|bank)[^\w]{0,8}\d{9}\b/i.test(text)) continue;
      if (id === "swift" && !/\b(swift|bic|bank)[^\w]{0,8}[A-Z]{6}[A-Z0-9]{2,5}\b/i.test(text)) continue;
      if (id === "passport_us" && !/\b(passport|travel|document)[^\w]{0,8}[A-Z]{2}\d{7}\b/i.test(text)) continue;
      if (id === "iban" && !/\b(iban|account|bank)[^\w]{0,8}[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b/i.test(text)) continue;
      if (id === "vin" && !/\b(vin|vehicle|car)[^\w]{0,8}[A-HJ-NPR-Z0-9]{17}\b/i.test(text)) continue;
      if (id === "gps" && !/\b(gps|lat|lon|geo|coordinates)[^\w]{0,8}[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+\b/i.test(text)) continue;
      if (id === "dob" && !/\b(dob|birth|birthday|born)[^\w]{0,8}\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}\b/i.test(text)) continue;
      if (id === "place_of_birth" && !/\b(place.*birth|pob|born.*in)[^\w]{0,8}[A-Za-z\s,]+\b/i.test(text)) continue;
      if (id === "employment" && !/\b(employer|company|job|work|position)[^\w]{0,8}[A-Za-z0-9\s&.,'-]+\b/i.test(text)) continue;
      if (id === "home_address" && !/\b(address|home|street|residence)[^\w]{0,8}\d{1,5}\s\w+\s\w+\b/i.test(text)) continue;
      
      return id;
    }
  }

  for (const pw of userPasswords) {
    if (pw && pw.length >= 4 && text.includes(pw.toLowerCase())) {
      if (/\b(password|pass|pwd|auth|login|secret)\b/i.test(text)) {
        return "user_password";
      }
    }
  }

  return null;
}

function safeAppendBanner(el) {
  if (document.body) document.body.appendChild(el);
  else window.requestAnimationFrame(() => safeAppendBanner(el));
}

function showAlertPopup(leakId, host) {
  const box = document.createElement("div");
  box.innerHTML = `⚠️ Allowed <b>${FRIENDLY_LABELS[leakId] || leakId}</b> leak to <b>${host}</b>`;
  box.style.cssText = `
    position: fixed !important;
    bottom: 20px !important;
    right: 20px !important;
    background: #ffc107 !important;
    color: black !important;
    font-weight: bold !important;
    padding: 12px !important;
    z-index: 2147483647 !important;
    border-radius: 8px !important;
    box-shadow: 0 0 10px rgba(0,0,0,0.5) !important;
    font-family: sans-serif !important;
    max-width: 300px !important;
  `;
  const btn = document.createElement("button");
  btn.textContent = "Block Site";
  btn.style.cssText = "margin-top:8px !important;padding:6px 12px !important;border-radius:4px !important;background:#b71c1c !important;color:white !important;border:none !important;display:block !important;cursor:pointer !important;";
  btn.onclick = () => {
    block.add(host);
    set("__dld_block__", [...block]);
    box.remove();
  };
  box.appendChild(btn);
  safeAppendBanner(box);
  setTimeout(() => box.remove(), 5000);
}

function showBlockedPopup(leakId, host) {
  const box = document.createElement("div");
  box.innerHTML = `❌ Blocked request for <b>${FRIENDLY_LABELS[leakId] || leakId}</b> leak to <b>${host}</b>`;
  box.style.cssText = `
    position: fixed !important;
    bottom: 20px !important;
    right: 20px !important;
    background: #d32f2f !important;
    color: white !important;
    font-weight: bold !important;
    padding: 12px !important;
    z-index: 2147483647 !important;
    border-radius: 8px !important;
    box-shadow: 0 0 10px rgba(0,0,0,0.5) !important;
    font-family: sans-serif !important;
    max-width: 300px !important;
  `;
  const btn = document.createElement("button");
  btn.textContent = "Unblock Site";
  btn.style.cssText = "margin-top:8px !important;padding:6px 12px !important;border-radius:4px !important;background:#0d47a1 !important;color:white !important;border:none !important;display:block !important;cursor:pointer !important;";
  btn.onclick = () => {
    block.delete(host);
    allow.add(host);
    set("__dld_block__", [...block]);
    set("__dld_allow__", [...allow]);
    box.innerHTML = "✅ Site unblocked. Future leaks will show a warning.";
    box.style.background = "#1565c0";
    setTimeout(() => box.remove(), 3000);
  };
  box.appendChild(btn);
  safeAppendBanner(box);
  setTimeout(() => box.remove(), 5000);
}

function prompt(host, msg, onAllow, onBlock) {
  const banner = document.createElement("div");
  banner.style.cssText = `position:fixed !important;top:0 !important;left:0 !important;width:100% !important;padding:14px !important;background:#d32f2f !important;color:#fff !important;font:700 14px Arial !important;text-align:center !important;z-index:2147483647 !important;border-radius:0 0 8px 8px !important`;
  banner.innerHTML = `
    Potential leak to <b>${host}</b><br><small>${msg}</small><br><br>
    <button id="dld-allow" style="border-radius:6px !important;padding:6px 12px !important;margin-right:10px !important;background:#fff !important;color:#000 !important;border:none !important;cursor:pointer !important;">Report False Alarm</button>
    <button id="dld-block" style="border-radius:6px !important;padding:6px 12px !important;background:#b71c1c !important;color:#fff !important;border:none !important;cursor:pointer !important;">Block Request</button>
  `;
  safeAppendBanner(banner);

  setTimeout(() => {
    const allowBtn = banner.querySelector("#dld-allow");
    const blockBtn = banner.querySelector("#dld-block");

    if (allowBtn) {
      allowBtn.onclick = () => {
        allow.add(host);
        block.delete(host);
        set("__dld_allow__", [...allow]);
        set("__dld_block__", [...block]);
        banner.style.background = "#1565c0";
        banner.textContent = "False alarm reported. Future leaks will warn only.";
        setTimeout(() => banner.remove(), 3000);
        onAllow?.();
      };
    }

    if (blockBtn) {
      blockBtn.onclick = () => {
        block.add(host);
        allow.delete(host);
        set("__dld_allow__", [...allow]);
        set("__dld_block__", [...block]);
        banner.style.background = "#2e7d32";
        banner.textContent = "Request blocked.";
        setTimeout(() => banner.remove(), 3000);
        onBlock?.();
      };
    }
  }, 100);
  
  setTimeout(() => {
    if (banner.parentNode) banner.remove();
  }, 10000);
}

const originalFetch = window.fetch;
window.fetch = function (input, init = {}) {
  try {
    const url = typeof input === "string" ? input : input.url;
    const h = hname(url);
    const body = init.body || (typeof input === "object" && input.body);
    let parsed;
    try { parsed = typeof body === "string" ? JSON.parse(body) : body; } catch { parsed = body; }
    const leak = detect(parsed || body);

    if (leak && third(url) && !isWhitelisted(h)) {
      if (block.has(h)) {
        showBlockedPopup(leak, h);
        return Promise.reject(new Error("Blocked by DLD"));
      }
      if (allow.has(h)) {
        showAlertPopup(leak, h);
        return originalFetch.apply(this, arguments);
      }
      return new Promise((resolve, reject) => {
        prompt(
          h,
          `fetch → ${FRIENDLY_LABELS[leak] || leak}`,
          () => originalFetch.apply(this, arguments).then(resolve).catch(reject),
          () => reject(new Error("Blocked by DLD"))
        );
      });
    }
    return originalFetch.apply(this, arguments);
  } catch {
    return originalFetch.apply(this, arguments);
  }
};

const origOpen = XMLHttpRequest.prototype.open;
const origSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.open = function (method, url) {
  this._dld_url = url;
  return origOpen.apply(this, arguments);
};
XMLHttpRequest.prototype.send = function (body) {
  const url = this._dld_url;
  const h = hname(url);
  let parsed;
  try { parsed = typeof body === "string" ? JSON.parse(body) : body; } catch { parsed = body; }
  const leak = detect(parsed || body);

  if (leak && third(url) && !isWhitelisted(h)) {
    if (block.has(h)) {
      showBlockedPopup(leak, h);
      return;
    }
    if (allow.has(h)) {
      showAlertPopup(leak, h);
      return origSend.call(this, body);
    }
    prompt(
      h,
      `XHR → ${FRIENDLY_LABELS[leak] || leak}`,
      () => {
        showAlertPopup(leak, h);
        origOpen.call(this, "POST", url);
        origSend.call(this, body);
      },
      () => {}
    );
    return;
  }
  return origSend.call(this, body);
};

if (navigator.sendBeacon) {
  const originalSendBeacon = navigator.sendBeacon.bind(navigator);
  navigator.sendBeacon = function (url, data) {
    const h = hname(url);
    let parsed;
    try { parsed = typeof data === "string" ? JSON.parse(data) : data; } catch { parsed = data; }
    const leak = detect(parsed || data);

    if (leak && third(url) && !isWhitelisted(h)) {
      if (block.has(h)) {
        showBlockedPopup(leak, h);
        return false;
      }
      if (allow.has(h)) {
        showAlertPopup(leak, h);
        return originalSendBeacon(url, data);
      }
      prompt(
        h,
        `Beacon → ${FRIENDLY_LABELS[leak] || leak}`,
        () => {
          showAlertPopup(leak, h);
          return originalSendBeacon(url, data);
        },
        () => {}
      );
      return false;
    }
    return originalSendBeacon(url, data);
  };
}

if (typeof chrome !== "undefined" && chrome.storage?.local) {
  chrome.storage.local.get(["customPasswordList", "enabledPatterns", "dld_paused"], (res) => {
    userPasswords = Array.isArray(res.customPasswordList) ? res.customPasswordList : [];
    if (Array.isArray(res.enabledPatterns) && res.enabledPatterns.length > 0) {
      enabledIDs = new Set(res.enabledPatterns);
    }
    if (res.dld_paused === true) {
      console.warn("[DLD] Protection is paused");
    }
  });

  chrome.runtime?.onMessage?.addListener((msg) => {
    if (msg.type === "CUSTOM_PASSWORD_UPDATED") {
      chrome.storage.local.get("customPasswordList", ({ customPasswordList }) => {
        userPasswords = Array.isArray(customPasswordList) ? customPasswordList : [];
      });
    }
  });
}