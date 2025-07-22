const PATTERN_IDS = {
  

  user_password: false
};

const LABELS = {
  

  user_password: "Custom Password (Highly Recommended)"
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

  // Build UI first with defaults
  buildToggleUI();
  
  // Main load logic
  chrome.storage.local.get(["enabledPatterns", "customPasswordList"], ({ enabledPatterns, customPasswordList = [] }) => {
    // If no saved patterns, use defaults and save them
    if (!enabledPatterns || !Array.isArray(enabledPatterns)) {
      const defaultKeys = Object.entries(PATTERN_IDS)
        .filter(([_, val]) => val)
        .map(([key]) => key);
      enabledPatterns = defaultKeys;
      chrome.storage.local.set({ enabledPatterns });
    }

    // Update checkboxes with saved/default patterns
    const enabledSet = new Set(enabledPatterns);
    container.querySelectorAll(".toggle").forEach(cb => {
      cb.checked = enabledSet.has(cb.dataset.type);
    });
    
    passwordInput.value = (customPasswordList || []).join("\n");
    passwordWrapper.style.display = enabledSet.has("user_password") ? "block" : "none";
  });

  function buildToggleUI() {
    container.innerHTML = "";
    Object.keys(PATTERN_IDS).forEach(key => {
      const label = document.createElement("label");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "toggle";
      cb.dataset.type = key;
      cb.checked = PATTERN_IDS[key]; // Use default from PATTERN_IDS

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
