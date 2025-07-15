// content.js — runs in extension context, can use chrome.storage
chrome.storage.local.get("enabledPatterns", ({ enabledPatterns }) => {
  window.postMessage({
    type: "ENABLED_PATTERNS_RESULT",
    enabledPatterns: Array.isArray(enabledPatterns) && enabledPatterns.length
      ? enabledPatterns
      : Object.keys({
          ssn: true,
          passport_us: true,
          iban: true,
          cvv: true,
          vin: true,
          dl_us: true,
          home_address: true,
          gps: true,
          dob: true,
          place_of_birth: true,
          employment: true,
          email: true,
          phone: true,
          credit_card: true
        })
  }, "*");
});
