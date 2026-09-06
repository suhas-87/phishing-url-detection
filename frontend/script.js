/**
 * PhishGuard - Frontend Interaction & Machine Learning API Client
 * Connects the web UI to the Flask backend (/predict & /api/model-info)
 * Handles LocalStorage history, UI gauges, and navigation.
 */

const API_BASE = window.location.origin.includes("5000")
  ? window.location.origin
  : "http://127.0.0.1:5000";

const STORAGE_KEY = "phishguard_scan_history";

// DOM Elements
const navLinks = document.querySelectorAll(".nav-link");
const sections = document.querySelectorAll(".page-section");
const serverStatusBadge = document.getElementById("serverStatusBadge");
const urlScanForm = document.getElementById("urlScanForm");
const urlInput = document.getElementById("urlInput");
const clearInputBtn = document.getElementById("clearInputBtn");
const scanBtn = document.getElementById("scanBtn");
const scanLoader = document.getElementById("scanLoader");
const resultCard = document.getElementById("resultCard");
const sampleChips = document.querySelectorAll(".sample-chip");

const historyTable = document.getElementById("historyTable");
const historyTableBody = document.getElementById("historyTableBody");
const emptyHistoryMsg = document.getElementById("emptyHistoryMsg");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

// Model Info Stat Elements
const statModelName = document.getElementById("statModelName");
const statAccuracy = document.getElementById("statAccuracy");
const statF1 = document.getElementById("statF1");
const statDatasetSize = document.getElementById("statDatasetSize");
const modelComparisonBody = document.getElementById("modelComparisonBody");

// ==========================================
// 1. INITIALIZATION & NAVIGATION
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupInputHandlers();
  setupSampleChips();
  setupHistory();
  checkServerHealth();
  loadModelMetadata();
});

function setupNavigation() {
  navLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const targetId = link.getAttribute("data-target");

      navLinks.forEach((l) => l.classList.remove("active"));
      link.classList.add("active");

      sections.forEach((sec) => {
        if (sec.id === targetId) {
          sec.classList.remove("hidden");
          sec.classList.add("active-section");
        } else {
          sec.classList.add("hidden");
          sec.classList.remove("active-section");
        }
      });

      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });
}

function setupInputHandlers() {
  urlInput.addEventListener("input", () => {
    clearInputBtn.style.display = urlInput.value.trim() ? "block" : "none";
  });

  clearInputBtn.addEventListener("click", () => {
    urlInput.value = "";
    urlInput.focus();
    clearInputBtn.style.display = "none";
  });

  urlScanForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (url) {
      performScan(url);
    }
  });
}

function setupSampleChips() {
  sampleChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const url = chip.getAttribute("data-url");
      urlInput.value = url;
      clearInputBtn.style.display = "block";
      performScan(url);
    });
  });
}

// ==========================================
// 2. SERVER HEALTH & METADATA
// ==========================================

async function checkServerHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (res.ok) {
      const data = await res.json();
      serverStatusBadge.className = "server-status online";
      serverStatusBadge.querySelector(".status-text").textContent =
        `ML Online (${data.champion_algorithm || "Active"})`;
    } else {
      throw new Error("Server returned non-200");
    }
  } catch (err) {
    serverStatusBadge.className = "server-status offline";
    serverStatusBadge.querySelector(".status-text").textContent = "Backend Offline";
  }
}

async function loadModelMetadata() {
  try {
    const res = await fetch(`${API_BASE}/api/model-info`);
    if (!res.ok) return;
    const data = await res.json();

    if (data.best_model && statModelName) {
      statModelName.textContent = data.best_model;
    }
    if (data.metrics && statAccuracy) {
      statAccuracy.textContent = `${data.metrics.accuracy.toFixed(1)}%`;
    }
    if (data.metrics && statF1) {
      statF1.textContent = `${data.metrics.f1_score.toFixed(1)}%`;
    }
    if (data.dataset_stats && statDatasetSize) {
      const total = data.dataset_stats.total_samples || 3200;
      const train = data.dataset_stats.train_samples || 2560;
      const test = data.dataset_stats.test_samples || 640;
      statDatasetSize.textContent = `${total.toLocaleString()} URLs`;
      statDatasetSize.nextElementSibling.textContent =
        `80% Train (${train.toLocaleString()}) / 20% Test (${test.toLocaleString()})`;
    }

    // Populate comparison table if data available
    if (data.all_models && modelComparisonBody) {
      let rowsHtml = "";
      for (const [algName, metrics] of Object.entries(data.all_models)) {
        const isChampion = algName === data.best_model;
        rowsHtml += `
          <tr>
            <td><strong>${algName}</strong></td>
            <td>${metrics.accuracy.toFixed(2)}%</td>
            <td>${metrics.precision.toFixed(2)}%</td>
            <td>${metrics.recall.toFixed(2)}%</td>
            <td>${metrics.f1_score.toFixed(2)}%</td>
            <td>
              <span class="badge ${isChampion ? "legit-badge" : "info-badge"}">
                ${isChampion ? "CHAMPION" : "Evaluated"}
              </span>
            </td>
          </tr>
        `;
      }
      modelComparisonBody.innerHTML = rowsHtml;
    }
  } catch (err) {
    console.warn("Could not fetch model info metadata:", err);
  }
}

// ==========================================
// 3. SCANNING & MACHINE LEARNING INFERENCE
// ==========================================

async function performScan(targetUrl) {
  // Show loader, disable button
  scanLoader.classList.remove("hidden");
  resultCard.classList.add("hidden");
  scanBtn.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl }),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Server returned error (${res.status})`);
    }

    const result = await res.json();
    renderResult(result);
    saveScanToHistory(result);
  } catch (err) {
    renderError(err.message || "Failed to connect to ML backend.");
  } finally {
    scanLoader.classList.add("hidden");
    scanBtn.disabled = false;
  }
}

function renderResult(result) {
  const isPhish = result.prediction.toLowerCase() === "phishing";
  const statusClass = isPhish ? "phishing" : "legitimate";
  const badgeIcon = isPhish ? "🔴" : "🟢";
  const badgeText = isPhish ? "PHISHING DETECTED" : "SAFE URL";
  const riskClass = `risk-${(result.risk_level || "medium").toLowerCase()}`;

  // Build indicators HTML
  let indicatorsHtml = "";
  if (result.indicators && result.indicators.length > 0) {
    indicatorsHtml = `
      <div class="indicators-section">
        <div class="indicators-title">
          <span>🔍</span> Educational Threat Indicators (Extracted Features):
        </div>
        <div class="indicators-grid">
          ${result.indicators
            .map(
              (ind) => `
            <div class="indicator-pill ${ind.type}">
              <span class="indicator-icon">
                ${ind.type === "danger" ? "⚠️" : ind.type === "warning" ? "⚡" : "✅"}
              </span>
              <div class="indicator-text">
                <strong>${escapeHtml(ind.title)}</strong>
                <span>${escapeHtml(ind.description)}</span>
              </div>
            </div>
          `
            )
            .join("")}
        </div>
      </div>
    `;
  }

  // Build features table HTML
  let featuresTableHtml = "";
  if (result.features) {
    featuresTableHtml = `
      <div class="features-accordion">
        <button type="button" class="accordion-toggle" id="featuresToggleBtn">
          <span>⚙️</span> View Raw Extracted Feature Vector (11 Features) ▼
        </button>
        <div class="features-table-wrapper hidden" id="featuresWrapper">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Feature Name</th>
                <th>Extracted Value</th>
                <th>Security Significance</th>
              </tr>
            </thead>
            <tbody>
              ${Object.entries(result.features)
                .map(
                  ([k, v]) => `
                <tr>
                  <td><code>${escapeHtml(k)}</code></td>
                  <td><strong>${escapeHtml(String(v))}</strong></td>
                  <td style="color: var(--text-secondary); font-size: 0.8rem;">
                    ${getFeatureExplanation(k)}
                  </td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  resultCard.className = `result-card ${statusClass}`;
  resultCard.innerHTML = `
    <div class="result-header">
      <div class="result-verdict">
        <span class="verdict-badge ${statusClass}">
          ${badgeIcon} ${badgeText}
        </span>
        <span class="risk-level-tag ${riskClass}">
          Risk: ${escapeHtml(result.risk_level || "Unknown")}
        </span>
      </div>
      <div style="font-size: 0.85rem; color: var(--text-muted);">
        Model: <strong>${escapeHtml(result.model_used || "Random Forest")}</strong>
      </div>
    </div>

    <!-- Scanned URL Box -->
    <div class="target-url-box">
      <span class="target-url-text">${escapeHtml(result.url)}</span>
      <button type="button" class="copy-btn" id="copyUrlBtn">Copy</button>
    </div>

    <!-- Confidence Score Gauge -->
    <div class="confidence-container">
      <div class="confidence-header">
        <span>Model Confidence Probability</span>
        <span class="confidence-score-val">${result.confidence}%</span>
      </div>
      <div class="confidence-track">
        <div class="confidence-fill ${statusClass}" id="confidenceBar" style="width: 0%;"></div>
      </div>
    </div>

    <!-- Indicators -->
    ${indicatorsHtml}

    <!-- Features Drawer -->
    ${featuresTableHtml}
  `;

  resultCard.classList.remove("hidden");

  // Animate confidence bar
  setTimeout(() => {
    const bar = document.getElementById("confidenceBar");
    if (bar) bar.style.width = `${Math.min(100, Math.max(10, result.confidence))}%`;
  }, 50);

  // Setup copy button
  const copyBtn = document.getElementById("copyUrlBtn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(result.url);
      copyBtn.textContent = "Copied!";
      setTimeout(() => (copyBtn.textContent = "Copy"), 2000);
    });
  }

  // Setup features toggle
  const toggleBtn = document.getElementById("featuresToggleBtn");
  const featWrapper = document.getElementById("featuresWrapper");
  if (toggleBtn && featWrapper) {
    toggleBtn.addEventListener("click", () => {
      const isClosed = featWrapper.classList.contains("hidden");
      if (isClosed) {
        featWrapper.classList.remove("hidden");
        toggleBtn.innerHTML = "<span>⚙️</span> Hide Raw Feature Vector ▲";
      } else {
        featWrapper.classList.add("hidden");
        toggleBtn.innerHTML = "<span>⚙️</span> View Raw Extracted Feature Vector (11 Features) ▼";
      }
    });
  }
}

function renderError(message) {
  resultCard.className = "result-card";
  resultCard.innerHTML = `
    <div class="result-header">
      <div class="result-verdict">
        <span class="verdict-badge phishing">⚠️ SCAN FAILED</span>
      </div>
    </div>
    <p style="color: #f87171; margin-bottom: 1rem;">${escapeHtml(message)}</p>
    <p style="color: var(--text-secondary); font-size: 0.85rem;">
      Make sure the Flask backend is active (<code>python backend/app.py</code>) and listening on port 5000.
    </p>
  `;
  resultCard.classList.remove("hidden");
}

function getFeatureExplanation(featName) {
  const map = {
    url_length: "Phishing URLs often exceed 75+ characters to hide malicious destinations.",
    domain_length: "Excessively long domain names frequently indicate brand spoofing.",
    num_dots: "Multiple dots indicate deep subdomains used to bypass filters.",
    num_hyphens: "Hyphens are heavily used in typo-squatting (e.g. secure-login-bank).",
    num_digits: "Unusual density of numbers indicates random token padding or IP hosts.",
    num_special_chars: "Special characters (@, ?, =, &, %) are used in deceptive query strings.",
    num_slashes: "High slash count indicates deep directory nesting to evade scanners.",
    has_https: "1 indicates valid HTTPS protocol, 0 indicates unencrypted HTTP.",
    is_ip_address: "1 if URL host is raw IPv4/IPv6, a major indicator of phishing.",
    num_subdomains: "Deep subdomain chains disguise attacker infrastructure as trusted brands.",
    suspicious_words_count: "Counts sensitive keywords: login, verify, account, update, secure, bank, signin, confirm.",
  };
  return map[featName] || "Numerical structural feature used by the classifier.";
}

// ==========================================
// 4. SCAN HISTORY (LOCAL STORAGE)
// ==========================================

function getScanHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function saveScanToHistory(result) {
  const history = getScanHistory();
  const item = {
    id: Date.now(),
    url: result.url,
    prediction: result.prediction,
    confidence: result.confidence,
    risk_level: result.risk_level,
    time: new Date().toLocaleString(),
  };

  // Keep latest 25 scans
  history.unshift(item);
  if (history.length > 25) history.pop();

  localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  renderHistoryTable();
}

function setupHistory() {
  renderHistoryTable();

  clearHistoryBtn.addEventListener("click", () => {
    if (confirm("Are you sure you want to clear your scan history?")) {
      localStorage.removeItem(STORAGE_KEY);
      renderHistoryTable();
    }
  });
}

function renderHistoryTable() {
  const history = getScanHistory();

  if (!history || history.length === 0) {
    emptyHistoryMsg.classList.remove("hidden");
    historyTable.classList.add("hidden");
    return;
  }

  emptyHistoryMsg.classList.add("hidden");
  historyTable.classList.remove("hidden");

  historyTableBody.innerHTML = history
    .map((item) => {
      const isPhish = item.prediction.toLowerCase() === "phishing";
      const badgeClass = isPhish ? "phish-badge" : "legit-badge";
      const riskClass = `risk-${(item.risk_level || "low").toLowerCase()}`;

      return `
      <tr>
        <td style="color: var(--text-muted); font-size: 0.8rem; white-space: nowrap;">${item.time}</td>
        <td style="font-family: var(--font-mono); font-size: 0.85rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(item.url)}">
          ${escapeHtml(item.url)}
        </td>
        <td><span class="badge ${badgeClass}">${item.prediction}</span></td>
        <td><strong>${item.confidence}%</strong></td>
        <td><span class="risk-level-tag ${riskClass}" style="font-size: 0.75rem;">${item.risk_level}</span></td>
        <td>
          <button type="button" class="secondary-btn" style="padding: 4px 10px; font-size: 0.75rem;" onclick="reScan('${escapeHtml(item.url)}')">
            Re-scan
          </button>
        </td>
      </tr>
    `;
    })
    .join("");
}

// Global re-scan helper
window.reScan = function (url) {
  const scannerLink = document.querySelector('.nav-link[data-target="scanner"]');
  if (scannerLink) scannerLink.click();
  urlInput.value = url;
  clearInputBtn.style.display = "block";
  performScan(url);
};

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
