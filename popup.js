const PATTERN_IDS = {
  phoneNumber: true,
  creditCardNumber: true,
  cryptoAddresses: true,
  emailAddress: true,
  ipAddresses: true,
  gpsCoordinates: true,
  dateOfBirth: false,
  ssn: true,
  passportUS: true,
  iban: false,
  aba: false,
  swift: true,
  cvv: true,
  vin: false,
  dl_us: true,
  homeAddress: true,
  placeOfBirth: false,
  employmentInformation: false,
  user_password: false
};

const LABELS = {
  phoneNumber: "Phone Number",
  creditCardNumber: "Credit Card Number",
  cryptoAddresses: "Crypto Addresses",
  emailAddress: "Email Address",
  ipAddresses: "IP Addresses",
  gpsCoordinates: "GPS Coordinates",
  dateOfBirth: "Date of Birth",
  ssn: "Social Security Number",
  passportUS: "Passport (US)",
  iban: "IBAN Code",
  aba: "ABA Routing Number",
  swift: "SWIFT Code",
  cvv: "CVV (4-digits on back)",
  vin: "Vehicle Identification Number (VIN)",
  dl_us: "Driver's License",
  homeAddress: "Home Address",
  placeOfBirth: "Place of Birth",
  employmentInformation: "Employment Info",
  user_password: "Custom Password (Set Below)"
};

document.addEventListener("DOMContentLoaded", () => {
  console.log("📦 DOMContentLoaded");

  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".tab-content");
  const pauseBtn = document.getElementById("pauseBtn");
  const resumeBtn = document.getElementById("resumeBtn");
  const statusTxt = document.getElementById("status");
  const container = document.getElementById("toggleContainer");
  const passwordInput = document.getElementById("customPasswordInput");
  const passwordSave = document.getElementById("savePasswordBtn");
  const passwordWrapper = document.getElementById("passwordWrapper");

  // Tab logic
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(tab.dataset.tab).classList.add("active");
    });
  });

  // Pause/resume logic
  function updateStatus(paused) {
    statusTxt.textContent = paused ? "Protection is paused." : "Protection is active.";
    pauseBtn.style.display = paused ? "none" : "inline-block";
    resumeBtn.style.display = paused ? "inline-block" : "none";
  }

  chrome.storage.local.get("dld_paused", ({ dld_paused = false }) => {
    updateStatus(dld_paused);
  });

  pauseBtn.addEventListener("click", () => {
    chrome.storage.local.set({ dld_paused: true }, () => updateStatus(true));
  });

  resumeBtn.addEventListener("click", () => {
    chrome.storage.local.set({ dld_paused: false }, () => updateStatus(false));
  });

  // Main load logic
  chrome.storage.local.get(["enabledPatterns", "customPasswordList"], ({ enabledPatterns = [], customPasswordList = [] }) => {
    const defaultKeys = Object.entries(PATTERN_IDS)
      .filter(([_, val]) => val)
      .map(([key]) => key);

    const same =
      enabledPatterns.length === defaultKeys.length &&
      defaultKeys.every(k => enabledPatterns.includes(k));

    const useSet = new Set(same ? enabledPatterns : defaultKeys);
    if (!same) chrome.storage.local.set({ enabledPatterns: [...useSet] });

    buildToggleUI(useSet);
    passwordInput.value = (customPasswordList || []).join("\n");
    passwordWrapper.style.display = useSet.has("user_password") ? "block" : "none";
  });

  function buildToggleUI(activeSet) {
    container.innerHTML = "";
    Object.keys(PATTERN_IDS).forEach(key => {
      const label = document.createElement("label");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "toggle";
      cb.dataset.type = key;
      cb.checked = activeSet.has(key);

      label.appendChild(cb);
      label.appendChild(document.createTextNode(" " + (LABELS[key] || key)));
      container.appendChild(label);
    });

    container.querySelectorAll(".toggle").forEach(tg => {
      tg.addEventListener("change", () => {
        const type = tg.dataset.type;
        chrome.storage.local.get("enabledPatterns", ({ enabledPatterns = [] }) => {
          chrome.runtime.sendMessage({ type: "ENABLED_PATTERNS_UPDATED" });

          const set = new Set(enabledPatterns);
          tg.checked ? set.add(type) : set.delete(type);
          chrome.storage.local.set({ enabledPatterns: [...set] }, () => {
            if (type === "user_password") {
              passwordWrapper.style.display = tg.checked ? "block" : "none";
            }
          });
        });
      });
    });
  }

  // Save multiple passwords
  passwordSave.addEventListener("click", () => {
    const raw = passwordInput.value.trim();
    if (raw) {
      const pwList = [...new Set(raw.split(/[\n,]+/).map(p => p.trim()).filter(Boolean))];
      chrome.storage.local.set({ customPasswordList: pwList }, () => {
        chrome.runtime.sendMessage({ type: "CUSTOM_PASSWORD_UPDATED" });
        alert("✅ Password(s) saved and will now be detected.");
      });
    } else {
      alert("⚠️ Please enter a valid password.");
    }
  });
});
// Tab switching
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(tab.dataset.tab).classList.add("active");
    });
  });

  // Check for file:// access permission
  if (chrome.extension.isAllowedFileSchemeAccess) {
    chrome.extension.isAllowedFileSchemeAccess(allowed => {
      if (!allowed) {
        const fileWarning = document.getElementById("fileWarning");
        if (fileWarning) fileWarning.style.display = "block";
      }
    });
  }
});
