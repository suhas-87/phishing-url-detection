# PhishGuard – Phishing URL Detection & Website Security Intelligence System
### AI-Powered Cyber Threat Intelligence & Academic Machine Learning Project
**Designed for 3rd-Year BCA (Bachelor of Computer Applications) Capstone Demonstration & Viva**

---

## 📌 1. Project Overview

Phishing is one of the most pervasive cybersecurity threats, responsible for over 80% of reported security incidents globally. Attackers craft fraudulent hyperlinks to impersonate legitimate services (such as online banking, email providers, payment gateways, and social networks) to harvest sensitive credentials, financial details, and personal identity data.

Traditional cyber defense mechanisms rely heavily on **static domain blacklists** (such as Google Safe Browsing or Spamhaus). While blacklists are effective against known threats, they fail against zero-day phishing attacks—malicious URLs configured minutes prior to an attack.

**PhishGuard** addresses this vulnerability by combining **Supervised Machine Learning** with **Live Destination Intelligence**:
1. **Machine Learning Classifier**: Extracts 11 structural, lexical, and protocol features to classify URLs as **Legitimate (Safe)** or **Phishing (Malicious)**.
2. **Deep Domain & Security Intelligence**: Concurrently retrieves real SSL/TLS certificates, WHOIS registration, domain age, DNS records, hosting provider/ASN, website title/metadata, and redirect chains.
3. **Safe Redirection Guard**: Prevents open redirect attacks by verifying destination safety and prompting users with a security confirmation modal before opening external links.
4. **Actionable Threat Diagnostics**: Fully disables redirection for dangerous URLs, surfacing flagged keywords, IP host alerts, and protocol risks.

---

## 🚀 2. Key Features

- **Genuine Machine Learning Engine**: Implements and benchmarks three classification algorithms: **Logistic Regression**, **Decision Tree Classifier**, and **Random Forest Classifier**.
- **Automated Model Selection**: Automatically identifies and exports the best-performing model based on F1-Score and Accuracy (`model/phishing_model.pkl`).
- **11-Point URL Feature Extractor**: Purely numerical feature extraction covering length metrics, symbol frequency, domain structure, protocol security, IP hosts, and sensitive keyword analysis.
- **7-Step Scanning Animation**: Interactive, multi-stage progress bar showing live verification phases (URL syntax -> domain reputation -> ML classifier -> SSL verification -> WHOIS -> metadata -> report compilation).
- **Safe Website Report Card**: When a URL is verified as safe, compiles a comprehensive intelligence report:
  - 🛡️ **Security Status**: Trust Score (0–100), ML confidence, Risk: Low, timestamp.
  - 🌐 **Domain Information**: Domain name, creation date, expiration date, calculated domain age, registrar, nameservers.
  - 🏢 **Organization Information**: Website owner / organization name, country, city.
  - 🔒 **SSL & TLS Security**: Certificate status, issuer, subject, valid until, TLS protocol, cipher.
  - 🖥️ **Server & Hosting**: IP address, hosting provider / ISP, network ASN, server location, web server software header.
  - 📊 **Website Content & Metadata**: Favicon preview, website title, description, redirect count, final destination URL.
- **Secure Redirection Guard**: "Visit Safe Website →" button prompts a security confirmation modal with anti-open-redirect validation before opening the destination in a new tab (`rel="noopener noreferrer"`).
- **Phishing Warning Diagnostic**: Strong alert banner, high-risk score, explicit "Do not visit this website" recommendation, flagged keyword indicators, and completely disabled redirection (`⛔ Redirect Disabled for Phishing URL`).
- **One-Click Report History**: Persistent log in HTML5 `localStorage` displaying URL, verdict, trust score, and timestamp. Clicking any previous scan immediately reloads the complete report!
- **One-Click Windows Launcher**: Windows batch script (`run_project.bat`) that verifies the environment, checks models, launches the server, and opens the browser automatically.

---

## 🏗️ 3. System Architecture & Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                       Target URL                            │
│           (e.g., https://www.wikipedia.org)                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│           Feature Extraction Engine (backend/)              │
│  - URL & Domain Length       - HTTPS Protocol (0/1)        │
│  - Dot / Hyphen / Slash Ct   - Raw IP Host (0/1)           │
│  - Digit / Special Char Ct   - Subdomain Hierarchy Count   │
│  - Sensitive Keywords (login, verify, secure, bank, etc.)   │
└──────────────────────────────┬──────────────────────────────┘
                               │ [11-Dimensional Vector]
                               ▼
┌─────────────────────────────────────────────────────────────┐
│          Trained Classifier (Random Forest ML)              │
│       model/phishing_model.pkl (Scikit-Learn Pipeline)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼
   [Legitimate / Safe URL]             [Phishing / Dangerous URL]
              │                                 │
              ▼                                 ▼
┌───────────────────────────────┐ ┌───────────────────────────┐
│ Concurrent Deep Intelligence  │ │ Threat Diagnostics        │
│ - SSL Certificate Inspection  │ │ - Highlight Flagged Words │
│ - WHOIS & Domain Age Calc     │ │ - Protocol / IP Warnings  │
│ - DNS Resolution & IP Lookup  │ │ - Risk Recommendation     │
│ - Hosting Provider & ASN      │ │ - Redirection Disabled    │
│ - Metadata, Title & Favicon   │ └─────────────┬─────────────┘
└─────────────┬─────────────────┘               │
              │                                 │
              ▼                                 ▼
┌───────────────────────────────┐ ┌───────────────────────────┐
│ Safe Website Report Card      │ │ Phishing Warning Alert    │
│ - Security Trust Score (0-100)│ │ - Risk: Critical          │
│ - 6 Structured Intel Cards    │ │ - Disabled Redirect Button│
│ - Protected Outbound Modal    │ └───────────────────────────┘
└───────────────────────────────┘
```

---

## 📁 4. Project Folder Structure

```
Phishing-URL-Detection-System/
│
├── dataset/
│   ├── urls.csv                     # Balanced dataset of 3,200 labeled URLs (0 = Safe, 1 = Phishing)
│   └── generate_dataset.py          # Script to generate/expand balanced, realistic datasets
│
├── model/
│   ├── phishing_model.pkl           # Saved champion ML model (Joblib binary)
│   ├── model_metadata.json          # Metrics, algorithm comparisons, and feature lists
│   └── test_data.pkl                # Cached test split for reproducibility
│
├── backend/
│   ├── app.py                       # Flask web application & REST API server
│   ├── feature_extractor.py         # 11-point URL numerical feature extraction engine
│   ├── url_analyzer.py              # Deep destination intelligence (WHOIS, SSL, DNS, Server, Metadata)
│   ├── train_model.py               # Loads data, trains LR/DT/RF, evaluates & exports champion
│   ├── evaluate_model.py            # Generates metrics & confusion matrix plot
│   └── requirements.txt             # Python package dependencies
│
├── frontend/
│   ├── index.html                   # SOC-themed cybersecurity web dashboard
│   ├── style.css                    # Glassmorphism dark styles & neon indicators
│   └── script.js                    # Multi-step progress, reports, modal & history manager
│
├── screenshots/
│   └── confusion_matrix.png         # Generated high-resolution confusion matrix heatmap
│
├── README.md                        # Academic project documentation & viva guide
└── run_project.bat                  # One-click Windows startup batch script
```

---

## 🔍 5. Feature Extraction Breakdown (11 Features)

Every URL is transformed into an 11-dimensional numerical vector using `backend/feature_extractor.py`.

| # | Feature Name | Data Type | Security Rationale |
|---|--------------|-----------|--------------------|
| 1 | `url_length` | Integer | Phishing links often exceed 75+ characters to pack tokens and disguise true destinations. |
| 2 | `domain_length` | Integer | Unusually long hostnames typically indicate multi-layered brand impersonation. |
| 3 | `num_dots` | Integer | Phishers use multiple dots to create misleading nested subdomain structures. |
| 4 | `num_hyphens` | Integer | Hyphens are heavily leveraged in brand typo-squatting (e.g., `paypal-update-login.com`). |
| 5 | `num_digits` | Integer | High digit counts correlate with raw IP addresses, session IDs, and obfuscated tokens. |
| 6 | `num_special_chars` | Integer | Frequency of `@`, `?`, `=`, `_`, `%`, `&`, `+`, `#` used to confuse URL parsers. |
| 7 | `num_slashes` | Integer | Measures path depth; phishing kits frequently hide forms deep in multi-tier directories. |
| 8 | `has_https` | Binary (0/1) | 1 if HTTPS, 0 if HTTP. Unencrypted HTTP is an immediate indicator of malicious/negligent sites. |
| 9 | `is_ip_address` | Binary (0/1) | 1 if hostname is a raw IPv4/IPv6 address. Attackers use raw IPs when domains are banned. |
| 10 | `num_subdomains` | Integer | Subdomain count (e.g., `login.chase.com.security-verify.xyz` has 3 subdomains). |
| 11 | `suspicious_words_count` | Integer | Count of sensitive words: `login`, `verify`, `account`, `update`, `secure`, `bank`, `signin`, `confirm`. |

---

## 📊 6. Machine Learning Models & Performance Benchmark

Three supervised classification algorithms were trained on an **80/20 stratified split** of the 3,200 URL dataset:

| Algorithm | Test Accuracy | Precision | Recall | F1-Score | Status |
|-----------|---------------|-----------|--------|----------|--------|
| **Random Forest Classifier** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | 🏆 **Selected Champion** |
| **Decision Tree Classifier** | 99.69% | 100.00% | 99.38% | 99.69% | Evaluated Benchmark |
| **Logistic Regression** | 99.69% | 100.00% | 99.38% | 99.69% | Evaluated Baseline |

---

## ⚙️ 7. Installation & Setup Instructions

### Method A: One-Click Startup (Windows)
Double-click `run_project.bat` in the project root directory.
The script will automatically:
1. Verify Python installation
2. Generate the dataset if missing
3. Train the machine learning model if missing
4. Generate the confusion matrix visualization
5. Launch the Flask backend server on `http://127.0.0.1:5000`
6. Open your default web browser to the PhishGuard dashboard

---

### Method B: Manual Step-by-Step Setup

```bash
# 1. Open terminal and navigate to project
cd "Phishing-URL-Detection-System"

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Start the Flask application
cd backend
python app.py

# 4. Open web browser
# http://127.0.0.1:5000
```

---

## 📡 8. REST API Specification

### 1. Analyze URL
- **Endpoint**: `POST /predict` (alias: `POST /analyze`)
- **Headers**: `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "url": "https://www.wikipedia.org"
  }
  ```
- **Response (Safe)**:
  ```json
  {
    "url": "https://www.wikipedia.org",
    "prediction": "Legitimate",
    "is_safe": true,
    "confidence": 100.0,
    "risk_level": "Low",
    "trust_score": 99,
    "can_redirect": true,
    "domain_info": {
      "domain_name": "wikipedia.org",
      "creation_date": "2001-01-13",
      "domain_age": "25 years, 8 months",
      "registrar": "MarkMonitor, Inc."
    },
    "organization_info": {
      "name": "Wikimedia Foundation, Inc.",
      "country": "US"
    },
    "ssl_info": {
      "has_ssl": true,
      "issuer": "Let's Encrypt",
      "status": "Valid & Active"
    },
    "server_info": {
      "ip_address": "103.102.166.224",
      "hosting_provider": "Wikimedia Foundation, Inc",
      "country": "United States"
    },
    "website_metadata": {
      "title": "Wikipedia",
      "description": "Wikipedia is a free online encyclopedia...",
      "redirect_count": 1
    }
  }
  ```

### 2. Verify Safe Redirection
- **Endpoint**: `POST /api/verify-redirect`
- **Request Body**:
  ```json
  {
    "url": "https://www.wikipedia.org"
  }
  ```
- **Response**: `{"status": "authorized", "safe_url": "https://www.wikipedia.org"}`
*(Returns HTTP 403 if destination is classified as phishing)*

---

## 🎓 9. Viva Voce & Academic Q&A Preparation (BCA 3rd Year)

### Q1: What problem does this project solve?
> **Answer**: It addresses the limitation of traditional domain blacklists in detecting new, zero-day phishing links. By extracting lexical and structural URL features and classifying them using a trained Machine Learning model, it detects malicious sites instantly without requiring network traffic or visiting the malicious webpage.

### Q2: How does PhishGuard protect users during external redirection?
> **Answer**: Rather than automatically redirecting, PhishGuard requires explicit user confirmation via a security warning modal, strictly disables redirection for dangerous URLs, and re-validates the destination URL on the backend (`/api/verify-redirect`) to prevent open redirect vulnerabilities.

### Q3: Why did you choose Random Forest over Logistic Regression and Decision Trees?
> **Answer**: Random Forest is an ensemble learning method that constructs multiple decision trees during training and outputs the mode of classes. It minimizes overfitting, handles non-linear feature interactions (such as the relationship between hyphens, IP hosts, and missing HTTPS), and consistently yielded superior F1-Score and generalizability across test splits.

---

## 📄 License & Academic Attribution
This project was developed for the **3rd-Year BCA (Bachelor of Computer Applications)** Academic Capstone Curriculum.  
Free for educational and non-commercial research use.
