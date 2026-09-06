# PhishGuard – Phishing URL Detection System
### AI-Powered Cyber Threat Intelligence & Academic Machine Learning Project
**Designed for 3rd-Year BCA (Bachelor of Computer Applications) Capstone Demonstration & Viva**

---

## 📌 1. Project Overview

Phishing is one of the most widespread cybersecurity threats, responsible for over 80% of reported security incidents globally. Attackers craft fraudulent hyperlinks to impersonate legitimate services (such as online banking, email providers, payment gateways, and social networks) to harvest sensitive credentials, financial details, and personal identity data.

Traditional cyber defense mechanisms rely heavily on **static domain blacklists** (such as Google Safe Browsing or Spamhaus). While blacklists are effective against known threats, they fail against zero-day phishing attacks—malicious URLs configured minutes prior to an attack.

**PhishGuard** addresses this vulnerability using **Supervised Machine Learning**. By extracting **11 structural, lexical, and protocol features** directly from URL strings, PhishGuard classifies URLs as **Legitimate (Safe)** or **Phishing (Malicious)** in real time without querying the remote web server or exposing the user to malware.

---

## 🚀 2. Key Features

- **Genuine Machine Learning Engine**: Implements and benchmarks three classification algorithms: **Logistic Regression**, **Decision Tree Classifier**, and **Random Forest Classifier**.
- **Automated Model Selection**: Automatically identifies and exports the best-performing model based on F1-Score and Accuracy (`model/phishing_model.pkl`).
- **11-Point URL Feature Extractor**: Purely numerical feature extraction covering length metrics, symbol frequency, domain structure, protocol security, IP hosts, and sensitive keyword analysis.
- **Explainable AI Indicators**: For every scanned URL, PhishGuard provides human-readable threat indicators detailing *why* a URL was flagged (e.g., raw IP host, nested subdomains, missing HTTPS, suspicious keywords).
- **RESTful Flask API**: Lightweight, production-grade backend exposing `/predict`, `/api/health`, and `/api/model-info` endpoints.
- **Cybersecurity SOC-Themed Dashboard**: Dark-mode user interface with neon glowing badges, real-time confidence gauges, sample test chips, and raw feature vector inspectors.
- **Browser Scan History**: Persists past scans in HTML5 `localStorage` with timestamps, verdicts, and one-click re-scan functionality.
- **Academic Evaluation Suite**: Generates a high-resolution confusion matrix heatmap (`screenshots/confusion_matrix.png`) and comprehensive classification reports.
- **One-Click Windows Launcher**: Windows batch script (`run_project.bat`) that verifies the environment, checks models, launches the server, and opens the browser automatically.

---

## 🏗️ 3. System Architecture & Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                       Target URL                            │
│           (e.g., http://192.168.1.10/login.php)             │
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
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Flask REST API (backend/app.py)             │
│        Output: Verdict, Confidence %, Risk Level,           │
│                Indicators & Raw Feature Metrics             │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Web Dashboard (frontend/index.html)             │
│  - Real-Time Safety Badges (🟢 SAFE / 🔴 PHISHING)          │
│  - Animated Confidence Gauge & Threat Indicators            │
│  - LocalStorage Scan History & BCA Viva Reference Tabs      │
└─────────────────────────────────────────────────────────────┘
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
│   ├── train_model.py               # Loads data, trains LR/DT/RF, evaluates & exports champion
│   ├── evaluate_model.py            # Generates metrics & confusion matrix plot
│   └── requirements.txt             # Python package dependencies
│
├── frontend/
│   ├── index.html                   # SOC-themed cybersecurity web dashboard
│   ├── style.css                    # Glassmorphism dark styles & neon indicators
│   └── script.js                    # AJAX scanner, API integration & localStorage history
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

### Evaluation Metrics Explanation:
- **Accuracy**: Proportion of total predictions that were correct: $\frac{TP + TN}{TP + TN + FP + FN}$
- **Precision**: Out of all URLs flagged as phishing, how many were genuine threats: $\frac{TP}{TP + FP}$
- **Recall (Sensitivity)**: Out of all actual phishing URLs, how many did the model detect: $\frac{TP}{TP + FN}$
- **F1-Score**: The harmonic mean of Precision and Recall, ensuring balanced evaluation on binary classes: $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$

The confusion matrix visualization is automatically saved to:
`screenshots/confusion_matrix.png`

---

## ⚙️ 7. Installation & Setup Instructions

### Prerequisites
- Operating System: Windows 10/11, macOS, or Linux
- Python: Version 3.9, 3.10, 3.11, 3.12, 3.13, or 3.14
- Web Browser: Chrome, Edge, Firefox, or Safari

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

#### Step 1: Open Terminal / PowerShell
Navigate to the project root folder:
```bash
cd "Phishing-URL-Detection-System"
```

#### Step 2: (Optional) Create a Virtual Environment
```bash
python -m venv venv

# Activate on Windows:
venv\Scripts\activate

# Activate on macOS/Linux:
source venv/bin/activate
```

#### Step 3: Install Required Dependencies
```bash
pip install -r backend/requirements.txt
```

#### Step 4: Generate Dataset (if not present)
```bash
python dataset/generate_dataset.py
```
*Output: Generates `dataset/urls.csv` containing 3,200 balanced legitimate and phishing samples.*

#### Step 5: Train and Select Best ML Model
```bash
python backend/train_model.py
```
*Output: Trains Logistic Regression, Decision Tree, and Random Forest; selects the best model and saves `model/phishing_model.pkl` and `model/model_metadata.json`.*

#### Step 6: Evaluate Model & Generate Confusion Matrix
```bash
python backend/evaluate_model.py
```
*Output: Prints performance metrics to the terminal and saves `screenshots/confusion_matrix.png`.*

#### Step 7: Run the Flask Web Application
```bash
python backend/app.py
```

#### Step 8: Open in Web Browser
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📡 8. REST API Specification

### 1. Predict URL Classification
- **Endpoint**: `POST /predict`
- **Headers**: `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "url": "http://192.168.1.10/paypal-login-verify-account.php"
  }
  ```
- **Response (Phishing)**:
  ```json
  {
    "url": "http://192.168.1.10/paypal-login-verify-account.php",
    "prediction": "Phishing",
    "confidence": 100.0,
    "risk_level": "High",
    "model_used": "Random Forest",
    "indicators": [
      {
        "type": "danger",
        "title": "Raw IP Address Used",
        "description": "Domain '192.168.1.10' is a numeric IP address instead of a registered domain name."
      },
      {
        "type": "warning",
        "title": "No HTTPS Encryption",
        "description": "The URL uses unencrypted HTTP protocol, leaving communication vulnerable."
      },
      {
        "type": "danger",
        "title": "Sensitive Keywords Found",
        "description": "URL contains security-sensitive keyword(s): 'login', 'verify', 'account'."
      }
    ],
    "features": {
      "url_length": 51,
      "domain_length": 12,
      "num_dots": 4,
      "num_hyphens": 3,
      "num_digits": 9,
      "num_special_chars": 0,
      "num_slashes": 3,
      "has_https": 0,
      "is_ip_address": 1,
      "num_subdomains": 0,
      "suspicious_words_count": 3
    }
  }
  ```

### 2. System Health Check
- **Endpoint**: `GET /api/health`
- **Response**:
  ```json
  {
    "status": "online",
    "model_loaded": true,
    "champion_algorithm": "Random Forest"
  }
  ```

### 3. Model Information & Metadata
- **Endpoint**: `GET /api/model-info`
- **Response**: Returns metrics, algorithm comparisons, feature list, and dataset split counts.

---

## 🎓 9. Viva Voce & Academic Q&A Preparation (BCA 3rd Year)

### Q1: What problem does this project solve?
> **Answer**: It addresses the limitation of traditional domain blacklists in detecting new, zero-day phishing links. By extracting lexical and structural URL features and classifying them using a trained Machine Learning model, it detects malicious sites instantly without requiring network traffic or visiting the malicious webpage.

### Q2: Why did you choose Random Forest over Logistic Regression and Decision Trees?
> **Answer**: Random Forest is an ensemble learning method that constructs multiple decision trees during training and outputs the mode of classes. It minimizes overfitting, handles non-linear feature interactions (such as the relationship between hyphens, IP hosts, and missing HTTPS), and consistently yielded superior F1-Score and generalizability across test splits.

### Q3: How does feature extraction ensure that no rules are hardcoded?
> **Answer**: `feature_extractor.py` converts a URL into pure numerical numbers (counts of dots, hyphens, digits, length, binary flags). The decision boundary is calculated mathematically by the trained Random Forest weights and branch thresholds during training, rather than `if-else` heuristic rules.

### Q4: What is the difference between Precision and Recall in this project, and which is more critical?
> **Answer**: 
> - **Precision** measures: Of all URLs flagged as phishing, how many were truly phishing? High precision prevents legitimate websites from being blocked (low False Positives).
> - **Recall** measures: Of all actual phishing links, how many did the system catch? High recall prevents malicious sites from slipping through (low False Negatives).
> In cybersecurity, **Recall** is often prioritized because missing a phishing attack (False Negative) can lead to severe data theft, whereas a False Positive merely causes minor user verification.

### Q5: What is the purpose of the 80/20 train-test split?
> **Answer**: An 80/20 stratified split trains the model on 80% of historical data and reserves 20% completely unseen samples to evaluate real-world generalization and prevent data leakage or overfitting.

---

## 🔮 10. Future Enhancements

1. **Deep Learning Integration**: Incorporate Bidirectional LSTM or Transformer-based tokenizers (like BERT/RoBERTa) to analyze character-level sequence representations.
2. **Browser Extension**: Package the model into a lightweight Chrome/Firefox extension that intercepts links before navigation.
3. **WHOIS & DNS Integration**: Incorporate domain creation age, registrar reputation, and SSL certificate issuer attributes.
4. **Live Screenshot Computer Vision**: Take headless browser captures of pages and compare visual layouts to trusted brands using Convolutional Neural Networks (CNNs).

---

## 📄 License & Academic Attribution
This project was developed for the **3rd-Year BCA (Bachelor of Computer Applications)** Academic Capstone Curriculum.  
Free for educational and non-commercial research use.
