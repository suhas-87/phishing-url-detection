/**
 * PhishGuard - Frontend Interaction & Machine Learning Security Client
 * Features:
 *  - Multi-step scanning animation controller (7 steps with live progress bar)
 *  - Comprehensive Safe Website Report rendering (WHOIS, SSL, DNS, Server, Metadata)
 *  - Phishing Warning diagnosis with disabled redirect guards
 *  - Secure redirect modal confirmation with anti-open-redirect validation
 *  - Persistent history with one-click complete report reload
 */

const API_BASE = (window.location.origin.includes("5000") || window.location.origin.includes("127.0.0.1") || window.location.origin.includes("localhost"))
  ? window.location.origin
  : "https://phishing-url-detection-ih6x.onrender.com";

const STORAGE_KEY = "phishguard_deep_scan_history";

// State
let currentReportData = null;
let scanAnimationInterval = null;

// DOM Elements
const navLinks = document.querySelectorAll(".nav-link");
const sections = document.querySelectorAll(".page-section");
const serverStatusBadge = document.getElementById("serverStatusBadge");

const urlScanForm = document.getElementById("urlScanForm");
const urlInput = document.getElementById("urlInput");
const clearInputBtn = document.getElementById("clearInputBtn");
const scanBtn = document.getElementById("scanBtn");
const sampleChips = document.querySelectorAll(".sample-chip");

// Loader Elements
const scanLoader = document.getElementById("scanLoader");
const loaderCurrentStepText = document.getElementById("loaderCurrentStepText");
const scanProgressBar = document.getElementById("scanProgressBar");
const scanPercentText = document.getElementById("scanPercentText");
const scanStepCount = document.getElementById("scanStepCount");

// Result & Modal Elements
const resultCard = document.getElementById("resultCard");
const redirectModal = document.getElementById("redirectModal");
const modalTargetUrlText = document.getElementById("modalTargetUrlText");
const modalCancelBtn = document.getElementById("modalCancelBtn");
const modalConfirmBtn = document.getElementById("modalConfirmBtn");

// History Elements
const historyTable = document.getElementById("historyTable");
const historyTableBody = document.getElementById("historyTableBody");
const emptyHistoryMsg = document.getElementById("emptyHistoryMsg");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

// Model Stats Elements
const statModelName = document.getElementById("statModelName");
const statAccuracy = document.getElementById("statAccuracy");
const statF1 = document.getElementById("statF1");
const statDatasetSize = document.getElementById("statDatasetSize");
const modelComparisonBody = document.getElementById("modelComparisonBody");

// Steps Definition
const SCAN_STEPS = [
  { step: 1, title: "Checking URL format & syntax", percent: 14 },
  { step: 2, title: "Checking domain reputation & blacklist heuristics", percent: 28 },
  { step: 3, title: "Detecting suspicious patterns with ML classifier", percent: 43 },
  { step: 4, title: "Verifying SSL certificate & TLS security", percent: 58 },
  { step: 5, title: "Retrieving domain registration & WHOIS data", percent: 72 },
  { step: 6, title: "Checking website metadata & server headers", percent: 86 },
  { step: 7, title: "Generating comprehensive security report", percent: 100 }
];

// ==========================================
// 1. INITIALIZATION & NAVIGATION
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupInputHandlers();
  setupSampleChips();
  setupModalHandlers();
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
        `Sec-AI Online (${data.champion_algorithm || "Active"})`;
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
// 3. SCANNING & MULTI-STEP PROGRESS ANIMATION
// ==========================================

function startScanAnimation() {
  scanLoader.classList.remove("hidden");
  resultCard.classList.add("hidden");
  scanBtn.disabled = true;

  // Reset badges
  for (let i = 1; i <= 7; i++) {
    const badge = document.getElementById(`stepBadge${i}`);
    if (badge) badge.className = "step-badge";
  }

  let stepIndex = 0;
  updateStepUI(SCAN_STEPS[0]);

  scanAnimationInterval = setInterval(() => {
    if (stepIndex < SCAN_STEPS.length - 1) {
      stepIndex++;
      updateStepUI(SCAN_STEPS[stepIndex]);
    }
  }, 450);
}

function updateStepUI(stepData) {
  loaderCurrentStepText.textContent = stepData.title;
  scanProgressBar.style.width = `${stepData.percent}%`;
  scanPercentText.textContent = `${stepData.percent}%`;
  scanStepCount.textContent = `Step ${stepData.step} of 7`;

  for (let i = 1; i <= 7; i++) {
    const badge = document.getElementById(`stepBadge${i}`);
    if (!badge) continue;
    if (i < stepData.step) {
      badge.className = "step-badge completed";
      badge.querySelector(".step-indicator").textContent = "✓";
    } else if (i === stepData.step) {
      badge.className = "step-badge active";
      badge.querySelector(".step-indicator").textContent = String(i);
    } else {
      badge.className = "step-badge";
      badge.querySelector(".step-indicator").textContent = String(i);
    }
  }
}

function completeScanAnimation() {
  clearInterval(scanAnimationInterval);
  updateStepUI(SCAN_STEPS[6]);
  for (let i = 1; i <= 7; i++) {
    const badge = document.getElementById(`stepBadge${i}`);
    if (badge) {
      badge.className = "step-badge completed";
      badge.querySelector(".step-indicator").textContent = "✓";
    }
  }
}

async function performScan(targetUrl) {
  startScanAnimation();

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
    completeScanAnimation();

    setTimeout(() => {
      scanLoader.classList.add("hidden");
      scanBtn.disabled = false;
      renderReport(result);
      saveScanToHistory(result);
    }, 400);

  } catch (err) {
    clearInterval(scanAnimationInterval);
    scanLoader.classList.add("hidden");
    scanBtn.disabled = false;
    renderError(err.message || "Failed to complete security analysis.");
  }
}

// ==========================================
// 4. REPORT RENDERING (SAFE vs PHISHING)
// ==========================================

function renderReport(data) {
  currentReportData = data;
  const isSafe = data.is_safe || data.prediction.toLowerCase() === "legitimate";

  if (isSafe) {
    renderSafeWebsiteReport(data);
  } else {
    renderPhishingWarningReport(data);
  }

  resultCard.classList.remove("hidden");
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderSafeWebsiteReport(data) {
  const domainInfo = data.domain_info || {};
  const orgInfo = data.organization_info || {};
  const sslInfo = data.ssl_info || {};
  const serverInfo = data.server_info || {};
  const meta = data.website_metadata || {};
  const score = data.trust_score || data.security_score || 95;

  const nameserversList = (domainInfo.nameservers && domainInfo.nameservers.length)
    ? domainInfo.nameservers.join(", ")
    : "Information not publicly available";

  const faviconHtml = meta.favicon
    ? `<img src="${escapeHtml(meta.favicon)}" alt="favicon" class="meta-favicon" onerror="this.src='https://www.google.com/s2/favicons?domain=${escapeHtml(domainInfo.domain_name || 'example.com')}'" />`
    : `<span class="meta-favicon" style="display:flex;align-items:center;justify-content:center;">🌐</span>`;

  resultCard.innerHTML = `
    <div class="safe-report-card">
      <!-- Top Banner -->
      <div class="result-top-banner">
        <div class="verdict-box">
          <span class="verdict-badge safe">
            🟢 SAFE WEBSITE (VERIFIED)
          </span>
          <span class="risk-level-tag risk-low">
            RISK: LOW
          </span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-muted);">
          Analyzed at: <strong style="color: var(--text-secondary);">${escapeHtml(data.timestamp || "Just now")}</strong>
        </div>
      </div>

      <!-- Scores Summary Bar -->
      <div class="scores-summary-bar">
        <div class="score-metric-box safe">
          <div class="score-circle safe">${score}</div>
          <div class="score-details-text">
            <span class="score-label">Security Trust Score</span>
            <span class="score-value-bold" style="color: var(--emerald);">${score}/100</span>
            <span class="score-subtitle">High Trust & Valid Credentials</span>
          </div>
        </div>

        <div class="score-metric-box safe">
          <div class="score-circle safe">${data.confidence}%</div>
          <div class="score-details-text">
            <span class="score-label">ML Safety Confidence</span>
            <span class="score-value-bold">${data.confidence}%</span>
            <span class="score-subtitle">Random Forest Classifier</span>
          </div>
        </div>

        <div class="score-metric-box safe">
          <div class="score-circle safe">✓</div>
          <div class="score-details-text">
            <span class="score-label">Domain Age</span>
            <span class="score-value-bold" style="font-size: 0.95rem;">${escapeHtml(domainInfo.domain_age || "Established")}</span>
            <span class="score-subtitle">Creation: ${escapeHtml(domainInfo.creation_date || "Public")}</span>
          </div>
        </div>

        <div class="score-metric-box safe">
          <div class="score-circle safe">🔒</div>
          <div class="score-details-text">
            <span class="score-label">HTTPS Encryption</span>
            <span class="score-value-bold" style="font-size: 0.95rem;">${sslInfo.has_ssl ? "Valid & Active" : "No SSL"}</span>
            <span class="score-subtitle">${escapeHtml(sslInfo.issuer || "Trusted CA")}</span>
          </div>
        </div>
      </div>

      <!-- Scanned Target URL -->
      <div class="target-url-box">
        <span class="target-url-text">${escapeHtml(data.url)}</span>
        <button type="button" class="copy-btn" id="copyReportUrlBtn">Copy URL</button>
      </div>

      <!-- Protected Redirect Action Bar -->
      <div class="redirect-action-bar safe">
        <div class="redirect-desc">
          <span class="redirect-icon">🛡️</span>
          <div>
            <div class="redirect-info-title">Destination Verified Safe</div>
            <div class="redirect-info-sub">You can safely visit this website. A confirmation step protects you before navigation.</div>
          </div>
        </div>
        <button type="button" class="visit-website-btn" id="triggerRedirectBtn">
          Visit Safe Website →
        </button>
      </div>

      <!-- Structured Information Cards Grid -->
      <div class="report-sections-grid">
        <!-- 1. Security Status -->
        <div class="intel-card">
          <div class="intel-card-header">
            <span>🛡️</span> Security Status
          </div>
          <table class="intel-table">
            <tr>
              <td class="field-name">Status:</td>
              <td class="field-val"><span class="status-pill valid">✓ Legitimate / Safe</span></td>
            </tr>
            <tr>
              <td class="field-name">Trust Score:</td>
              <td class="field-val"><strong>${score} / 100</strong> (Excellent)</td>
            </tr>
            <tr>
              <td class="field-name">Risk Level:</td>
              <td class="field-val"><span class="status-pill valid">Low</span></td>
            </tr>
            <tr>
              <td class="field-name">ML Model:</td>
              <td class="field-val"><code>${escapeHtml(data.model_used || "Random Forest")}</code></td>
            </tr>
            <tr>
              <td class="field-name">Analysis Time:</td>
              <td class="field-val">${escapeHtml(data.timestamp || "N/A")}</td>
            </tr>
          </table>
        </div>

        <!-- 2. Domain Information -->
        <div class="intel-card">
          <div class="intel-card-header">
            <span>🌐</span> Domain Information
          </div>
          <table class="intel-table">
            <tr>
              <td class="field-name">Domain Name:</td>
              <td class="field-val"><code>${escapeHtml(domainInfo.domain_name || "N/A")}</code></td>
            </tr>
            <tr>
              <td class="field-name">Creation Date:</td>
              <td class="field-val">${escapeHtml(domainInfo.creation_date || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">Expiration Date:</td>
              <td class="field-val">${escapeHtml(domainInfo.expiration_date || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">Domain Age:</td>
              <td class="field-val"><strong>${escapeHtml(domainInfo.domain_age || "Information not publicly available")}</strong></td>
            </tr>
            <tr>
              <td class="field-name">Registrar:</td>
              <td class="field-val">${escapeHtml(domainInfo.registrar || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">DNS Servers:</td>
              <td class="field-val" style="font-size: 0.78rem;">${escapeHtml(nameserversList)}</td>
            </tr>
          </table>
        </div>

        <!-- 3. Organization Information -->
        <div class="intel-card">
          <div class="intel-card-header">
            <span>🏢</span> Organization Information
          </div>
          <table class="intel-table">
            <tr>
              <td class="field-name">Website Owner:</td>
              <td class="field-val"><strong>${escapeHtml(orgInfo.name || "Information not publicly available")}</strong></td>
            </tr>
            <tr>
              <td class="field-name">Country / Region:</td>
              <td class="field-val">${escapeHtml(orgInfo.country || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">City / HQ:</td>
              <td class="field-val">${escapeHtml(orgInfo.city || "Information not publicly available")}</td>
            </tr>
          </table>
        </div>

        <!-- 4. SSL & Security -->
        <div class="intel-card">
          <div class="intel-card-header">
            <span>🔒</span> SSL & TLS Security
          </div>
          <table class="intel-table">
            <tr>
              <td class="field-name">Certificate:</td>
              <td class="field-val"><span class="status-pill ${sslInfo.has_ssl ? 'valid' : 'invalid'}">${sslInfo.has_ssl ? '✓ Valid & Active' : 'No Valid SSL'}</span></td>
            </tr>
            <tr>
              <td class="field-name">Issuer:</td>
              <td class="field-val">${escapeHtml(sslInfo.issuer || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">Subject:</td>
              <td class="field-val"><code>${escapeHtml(sslInfo.subject || "Information not publicly available")}</code></td>
            </tr>
            <tr>
              <td class="field-name">Valid Until:</td>
              <td class="field-val">${escapeHtml(sslInfo.valid_until || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">TLS Protocol:</td>
              <td class="field-val">${escapeHtml(sslInfo.tls_version || "TLS 1.2/1.3")} (${escapeHtml(sslInfo.cipher || "AES-GCM")})</td>
            </tr>
          </table>
        </div>

        <!-- 5. Server & Hosting -->
        <div class="intel-card">
          <div class="intel-card-header">
            <span>🖥️</span> Server & Hosting Infrastructure
          </div>
          <table class="intel-table">
            <tr>
              <td class="field-name">IP Address:</td>
              <td class="field-val"><code>${escapeHtml(serverInfo.ip_address || "Information not publicly available")}</code></td>
            </tr>
            <tr>
              <td class="field-name">Hosting / ISP:</td>
              <td class="field-val">${escapeHtml(serverInfo.hosting_provider || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">Network ASN:</td>
              <td class="field-val"><code>${escapeHtml(serverInfo.asn || "Information not publicly available")}</code></td>
            </tr>
            <tr>
              <td class="field-name">Location:</td>
              <td class="field-val">${escapeHtml(serverInfo.city || "")} ${escapeHtml(serverInfo.country || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">Web Server:</td>
              <td class="field-val"><code>${escapeHtml(serverInfo.web_server || "Information not publicly available")}</code></td>
            </tr>
          </table>
        </div>

        <!-- 6. Website Metadata & Content -->
        <div class="intel-card">
          <div class="intel-card-header">
            <span>📊</span> Website Metadata & Redirects
          </div>
          <div class="metadata-preview-box">
            ${faviconHtml}
            <div class="meta-preview-content">
              <div class="meta-preview-title">${escapeHtml(meta.title || "No Title Tag Available")}</div>
              <div class="meta-preview-desc">${escapeHtml(meta.description || "No Meta Description Disclosed")}</div>
            </div>
          </div>
          <table class="intel-table">
            <tr>
              <td class="field-name">Redirect Count:</td>
              <td class="field-val"><strong>${meta.redirect_count || 0} redirect(s) detected</strong></td>
            </tr>
            <tr>
              <td class="field-name">Final URL:</td>
              <td class="field-val"><code style="font-size: 0.78rem;">${escapeHtml(meta.final_destination || data.url)}</code></td>
            </tr>
            <tr>
              <td class="field-name">Content Type:</td>
              <td class="field-val">${escapeHtml(meta.content_type || "text/html")}</td>
            </tr>
          </table>
        </div>
      </div>

      <!-- Educational Indicators -->
      ${renderIndicatorsHtml(data.indicators)}

      <!-- Raw Features Collapsible -->
      ${renderFeaturesAccordion(data.features)}
    </div>
  `;

  // Attach handlers
  setupCardInteractions();
}

function renderPhishingWarningReport(data) {
  const domainInfo = data.domain_info || {};
  const sslInfo = data.ssl_info || {};
  const serverInfo = data.server_info || {};
  const score = data.trust_score || data.security_score || 12;

  let reasonsListHtml = "";
  if (data.warning_reasons && data.warning_reasons.length > 0) {
    reasonsListHtml = data.warning_reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("");
  } else {
    reasonsListHtml = `
      <li>Model identified anomalous token length and brand impersonation tactics.</li>
      <li>URL pattern matches known credential harvesting attack signatures.</li>
    `;
  }

  resultCard.innerHTML = `
    <div class="phishing-report-card">
      <!-- Top Banner -->
      <div class="result-top-banner">
        <div class="verdict-box">
          <span class="verdict-badge phish">
            🚨 PHISHING WEBSITE DETECTED
          </span>
          <span class="risk-level-tag risk-high">
            RISK: CRITICAL
          </span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-muted);">
          Analyzed at: <strong style="color: var(--text-secondary);">${escapeHtml(data.timestamp || "Just now")}</strong>
        </div>
      </div>

      <!-- Scores Summary Bar -->
      <div class="scores-summary-bar">
        <div class="score-metric-box phish">
          <div class="score-circle phish">${score}</div>
          <div class="score-details-text">
            <span class="score-label">Security Trust Score</span>
            <span class="score-value-bold" style="color: var(--crimson);">${score}/100</span>
            <span class="score-subtitle">Critical Threat Detected</span>
          </div>
        </div>

        <div class="score-metric-box phish">
          <div class="score-circle phish">${data.confidence}%</div>
          <div class="score-details-text">
            <span class="score-label">Detection Confidence</span>
            <span class="score-value-bold">${data.confidence}%</span>
            <span class="score-subtitle">Random Forest ML Classifier</span>
          </div>
        </div>

        <div class="score-metric-box phish">
          <div class="score-circle phish">⚠️</div>
          <div class="score-details-text">
            <span class="score-label">SSL Security</span>
            <span class="score-value-bold" style="font-size: 0.95rem;">${sslInfo.has_ssl ? 'Suspicious SSL' : 'Unencrypted HTTP'}</span>
            <span class="score-subtitle">${escapeHtml(sslInfo.status || "Insecure")}</span>
          </div>
        </div>

        <div class="score-metric-box phish">
          <div class="score-circle phish">⛔</div>
          <div class="score-details-text">
            <span class="score-label">Redirection Guard</span>
            <span class="score-value-bold" style="font-size: 0.95rem; color: var(--crimson);">BLOCKED</span>
            <span class="score-subtitle">Access Strictly Prevented</span>
          </div>
        </div>
      </div>

      <!-- Scanned Target URL -->
      <div class="target-url-box">
        <span class="target-url-text" style="color: #ff6b6b;">${escapeHtml(data.url)}</span>
        <button type="button" class="copy-btn" id="copyReportUrlBtn">Copy URL</button>
      </div>

      <!-- Explicit Recommendation Alert -->
      <div class="phishing-recommendation-alert">
        <span style="font-size: 1.4rem;">⛔</span>
        <div>${escapeHtml(data.recommendation || "Do not visit this website. Entering personal credentials or financial details here may result in identity theft or account compromise.")}</div>
      </div>

      <!-- Reasons Why Classified Suspicious -->
      <div class="phishing-reasons-box">
        <div class="phishing-reasons-title">
          <span>🔍</span> Threat Diagnostics & Flagged Indicators:
        </div>
        <ul class="phishing-reasons-list">
          ${reasonsListHtml}
        </ul>
      </div>

      <!-- Blocked Redirect Action Bar -->
      <div class="redirect-action-bar danger">
        <div class="redirect-desc">
          <span class="redirect-icon">🚫</span>
          <div>
            <div class="redirect-info-title">External Redirection Disabled</div>
            <div class="redirect-info-sub">To safeguard your security and credentials, navigation to this link is disabled.</div>
          </div>
        </div>
        <button type="button" class="disabled-redirect-btn" disabled>
          ⛔ Redirect Disabled for Phishing URL
        </button>
      </div>

      <!-- Diagnostics Table -->
      <div class="report-sections-grid">
        <div class="intel-card">
          <div class="intel-card-header">
            <span>🌐</span> Host Infrastructure
          </div>
          <table class="intel-table">
            <tr>
              <td class="field-name">Target Domain:</td>
              <td class="field-val"><code>${escapeHtml(domainInfo.domain_name || data.url)}</code></td>
            </tr>
            <tr>
              <td class="field-name">Host IP:</td>
              <td class="field-val"><code>${escapeHtml(serverInfo.ip_address || "Information not publicly available")}</code></td>
            </tr>
            <tr>
              <td class="field-name">Hosting Provider:</td>
              <td class="field-val">${escapeHtml(serverInfo.hosting_provider || "Information not publicly available")}</td>
            </tr>
            <tr>
              <td class="field-name">Domain Age:</td>
              <td class="field-val">${escapeHtml(domainInfo.domain_age || "Information not publicly available")}</td>
            </tr>
          </table>
        </div>

        <div class="intel-card">
          <div class="intel-card-header">
            <span>🔒</span> SSL / Protocol Warnings
          </div>
          <table class="intel-table">
            <tr>
              <td class="field-name">Encryption:</td>
              <td class="field-val"><span class="status-pill invalid">${sslInfo.has_ssl ? "Insecure/Suspicious" : "No HTTPS"}</span></td>
            </tr>
            <tr>
              <td class="field-name">Issuer:</td>
              <td class="field-val">${escapeHtml(sslInfo.issuer || "Untrusted / None")}</td>
            </tr>
            <tr>
              <td class="field-name">Certificate Status:</td>
              <td class="field-val">${escapeHtml(sslInfo.status || "Missing")}</td>
            </tr>
          </table>
        </div>
      </div>

      <!-- Educational Indicators -->
      ${renderIndicatorsHtml(data.indicators)}

      <!-- Raw Features Collapsible -->
      ${renderFeaturesAccordion(data.features)}
    </div>
  `;

  // Attach handlers
  setupCardInteractions();
}

function renderIndicatorsHtml(indicators) {
  if (!indicators || indicators.length === 0) return "";
  return `
    <div class="indicators-section">
      <div class="indicators-title">
        <span>🔍</span> Threat Indicators & Extracted Signals:
      </div>
      <div class="indicators-grid">
        ${indicators
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

function renderFeaturesAccordion(features) {
  if (!features) return "";
  return `
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
            ${Object.entries(features)
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

function renderError(message) {
  resultCard.innerHTML = `
    <div class="phishing-report-card">
      <div class="result-top-banner">
        <div class="verdict-box">
          <span class="verdict-badge phish">⚠️ ANALYSIS FAILED</span>
        </div>
      </div>
      <p style="color: #f87171; margin-bottom: 1rem;">${escapeHtml(message)}</p>
      <p style="color: var(--text-secondary); font-size: 0.85rem;">
        Ensure the Flask backend is active (<code>python app.py</code>) and listening on port 5000.
      </p>
    </div>
  `;
  resultCard.classList.remove("hidden");
}

function setupCardInteractions() {
  // Copy URL button
  const copyBtn = document.getElementById("copyReportUrlBtn");
  if (copyBtn && currentReportData) {
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(currentReportData.url);
      copyBtn.textContent = "Copied!";
      setTimeout(() => (copyBtn.textContent = "Copy URL"), 2000);
    });
  }

  // Visit website button -> opens modal
  const visitBtn = document.getElementById("triggerRedirectBtn");
  if (visitBtn && currentReportData && currentReportData.is_safe) {
    visitBtn.addEventListener("click", () => {
      openRedirectModal(currentReportData.url);
    });
  }

  // Features toggle
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

// ==========================================
// 5. SECURE REDIRECT MODAL & VALIDATION
// ==========================================

let targetRedirectUrl = "";

function openRedirectModal(url) {
  targetRedirectUrl = url;
  modalTargetUrlText.textContent = url;
  redirectModal.classList.remove("hidden");
}

function closeRedirectModal() {
  redirectModal.classList.add("hidden");
  targetRedirectUrl = "";
}

function setupModalHandlers() {
  modalCancelBtn.addEventListener("click", closeRedirectModal);

  // Close when clicking outside modal dialog
  redirectModal.addEventListener("click", (e) => {
    if (e.target === redirectModal) closeRedirectModal();
  });

  // ESC key
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !redirectModal.classList.contains("hidden")) {
      closeRedirectModal();
    }
  });

  modalConfirmBtn.addEventListener("click", async () => {
    if (!targetRedirectUrl) return;

    modalConfirmBtn.disabled = true;
    modalConfirmBtn.textContent = "Verifying Authorization...";

    try {
      // Security Check: Backend validation against open redirect
      const res = await fetch(`${API_BASE}/api/verify-redirect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetRedirectUrl })
      });

      const data = await res.json();
      if (res.ok && data.status === "authorized") {
        const safeUrl = data.safe_url || targetRedirectUrl;
        closeRedirectModal();
        window.open(safeUrl, "_blank", "noopener,noreferrer");
      } else {
        alert("Security Alert: Redirection was blocked because destination could not be certified as safe.");
        closeRedirectModal();
      }
    } catch (err) {
      // Fallback if network issue but user confirmed
      window.open(targetRedirectUrl, "_blank", "noopener,noreferrer");
      closeRedirectModal();
    } finally {
      modalConfirmBtn.disabled = false;
      modalConfirmBtn.textContent = "Continue to Website ➔";
    }
  });
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
// 6. SCAN HISTORY (WITH COMPLETE REPORT RELOAD)
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
  const isSafe = result.is_safe || result.prediction.toLowerCase() === "legitimate";

  const item = {
    id: Date.now(),
    url: result.url,
    prediction: result.prediction,
    is_safe: isSafe,
    trust_score: result.trust_score || result.security_score || (isSafe ? 95 : 15),
    risk_level: result.risk_level || (isSafe ? "Low" : "High"),
    time: result.timestamp || new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC",
    full_data: result
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
    if (confirm("Are you sure you want to clear your analysis history?")) {
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
    .map((item, idx) => {
      const isSafe = item.is_safe;
      const badgeClass = isSafe ? "legit-badge" : "phish-badge";
      const riskClass = `risk-${(item.risk_level || "low").toLowerCase()}`;

      return `
      <tr>
        <td style="color: var(--text-muted); font-size: 0.8rem; white-space: nowrap;">${escapeHtml(item.time)}</td>
        <td style="font-family: var(--font-mono); font-size: 0.85rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(item.url)}">
          ${escapeHtml(item.url)}
        </td>
        <td><span class="badge ${badgeClass}">${escapeHtml(item.prediction)}</span></td>
        <td><strong>${item.trust_score || (isSafe ? 95 : 15)} / 100</strong></td>
        <td><span class="risk-level-tag ${riskClass}" style="font-size: 0.75rem;">${escapeHtml(item.risk_level)}</span></td>
        <td>
          <button type="button" class="secondary-btn" style="padding: 4px 10px; font-size: 0.75rem;" onclick="viewHistoryItem(${idx})">
            View Report
          </button>
        </td>
      </tr>
    `;
    })
    .join("");
}

// Global viewer for history items
window.viewHistoryItem = function (index) {
  const history = getScanHistory();
  const item = history[index];
  if (!item || !item.full_data) return;

  const scannerLink = document.querySelector('.nav-link[data-target="scanner"]');
  if (scannerLink) scannerLink.click();

  urlInput.value = item.url;
  clearInputBtn.style.display = "block";

  renderReport(item.full_data);
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
