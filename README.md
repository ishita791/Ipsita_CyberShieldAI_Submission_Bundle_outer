# CyberShield AI — Intelligent Phishing and URL Threat Detection System

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-F7931E.svg)](https://scikit-learn.org/)
[![Security Focus](https://img.shields.io/badge/Domain-Defensive%20Cybersecurity-00F5D4.svg)](#defensive-scope)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An intelligent defensive cybersecurity system that analyzes URLs and suspicious message texts to identify phishing attempts, explain specific indicators of risk, provide actionable security recommendations, and demonstrate supervised machine learning evaluation.

---

## 1. Project Overview

Phishing attacks remain the primary initial access vector in cybercrime and corporate data breaches. **CyberShield AI** provides an accessible, transparent, and non-intrusive threat analysis platform that:
- Evaluates URLs statically across **14 distinct lexical, structural, and information-theoretic indicators**.
- Analyzes message bodies for **social engineering triggers** (urgency deadlines, credential solicitation, coercion, and reward lures).
- Correlates message text with embedded URLs.
- Delivers a calibrated **0–100 risk score** categorized into discrete threat tiers (**Low, Medium, High, Critical**).
- Houses a supervised machine learning engine evaluated using **Stratified 80/20 train/test splits** (96.5% accuracy, 97.0% recall).
- Operates under a **strict defensive paradigm** without contacting external infrastructure.

---

## 2. Key Features

### 🔍 URL Threat Analysis
- **Lexical Dimensions**: Length, count of dots, hyphens, digits, and special characters.
- **Obfuscation Detection**: Identifies `@` userinfo symbols, hex encoding (`%20`), and Punycode (`xn--`) homographs.
- **Host Type Verification**: Flags raw IPv4 / IPv6 addresses used instead of registered domain names.
- **Protocol Inspection**: Checks for HTTPS encryption versus unencrypted HTTP.
- **URL Shortener Identification**: Cross-references configurable list of URL shortening services (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
- **Shannon Entropy Calculation**: Computes information entropy on hostnames to flag randomized or algorithmically generated domains (DGAs).
- **Subdomain Hierarchy**: Analyzes nesting depth to detect visual brand impersonation (`paypal.com.attacker.com`).

### ✉️ Email and Message Phishing Analysis
- **Urgency & Coercion Flags**: Identifies artificial deadlines (*"within 24 hours"*, *"account will be suspended"*).
- **Credential & Financial Harvesting**: Flags direct solicitation of passwords, OTPs, PINs, and credit card numbers.
- **Baiting & Lottery Scams**: Identifies unsolicited prize, lottery, or bonus claims.
- **Impersonation Detection**: Detects spoofed executive, banking, and tech brand names.
- **Embedded Link Cross-Inspection**: Automatically extracts URLs from message bodies and runs them through the URL analyzer.

### 📊 Transparent Scoring & Actionable Recommendations
- **Itemized Factor Contributions**: Every detected risk factor contributes a visible point weight toward the 0–100 score.
- **Discrete Risk Tiers**:
  - `0 – 34`: **Low Risk** (Standard structural baseline)
  - `35 – 64`: **Medium Risk** (Suspicious traits; manual verification advised)
  - `65 – 84`: **High Risk** (Strong phishing indicators; do not input credentials)
  - `85 – 100`: **Critical Risk** (Immediate danger; block domain and notify SOC)
- **Defensive Countermeasures**: Provides contextual mitigation advice (e.g., out-of-band verification, SOC escalations, browser inspection).

### 🧠 Machine Learning Engine
- Standardized 14-dimensional feature vector extraction.
- Stratified 80/20 train/test partition (`random_state=42`).
- Evaluation on test set:
  - **Accuracy**: 96.50%
  - **Precision**: 96.04%
  - **Recall**: 97.00%
  - **F1-Score**: 96.52%
- Transparent confusion matrix and feature importance ranking.

---

## 3. Technology Stack

- **Language**: Python 3.10+ (tested on Python 3.10, 3.11, and 3.12)
- **Dashboard Interface**: Streamlit
- **Data Manipulation**: Pandas, NumPy
- **Machine Learning**: Scikit-Learn
- **Visualization**: Plotly Express & Graph Objects
- **Model Persistence**: Joblib
- **Report Generation**: Python-docx / OpenXML Engine
- **Testing**: Python Standard Library `unittest`

---

## 4. Project Structure

```text
cybershield-ai/
│
├── CyberShieldAI_Project.ipynb     # Jupyter Notebook with full research & workflow
├── requirements.txt                # Pinned Python package dependencies
├── YourName_ProjectReport.docx     # Academic Microsoft Word project report (generic)
├── Ipsita_ProjectReport.docx       # Academic Microsoft Word project report (authored)
├── README.md                       # Comprehensive project & GitHub documentation
├── app.py                          # Streamlit interactive dashboard application
├── .gitignore                      # Git ignore rules for virtualenvs, cache, and secrets
│
├── detector/                       # Detection and analysis package
│   ├── __init__.py                 # Package initializer
│   ├── url_analyzer.py             # Lexical and structural URL feature extractor
│   ├── email_analyzer.py           # NLP social engineering & credential lure parser
│   ├── risk_scorer.py              # 0–100 risk scoring & mitigation recommendation engine
│   ├── ml_engine.py                # ML feature vector pipeline & classifier inference
│   └── train_model.py              # Reproducible training & evaluation pipeline script
│
├── data/                           # Data storage
│   └── sample_phishing_dataset.csv # 1,000-sample balanced academic benchmark dataset
│
└── tests/                          # Automated unit test suite (100% pass rate)
    ├── __init__.py
    ├── test_url_analyzer.py        # URL feature extraction & safety tests
    ├── test_email_analyzer.py      # Social engineering regex & extraction tests
    ├── test_risk_scorer.py         # Risk categorization tier & weights tests
    └── test_ml_pipeline.py         # Feature vector consistency & inference tests
```

---

## 5. Prerequisites

- Python 3.10, 3.11, or 3.12 installed on your system.
- Git (optional, for cloning and pushing to GitHub).

---

## 6. Installation & Execution Guide

### Option A: Local Windows Setup (PowerShell)

1. **Open PowerShell** in the project root directory.

2. **Create a virtual environment**:
   ```powershell
   python -m venv .venv
   ```

3. **Activate the virtual environment**:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   *(If script execution is restricted on Windows, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` first)*.

4. **Install required dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

5. **Launch the Streamlit Application**:
   ```powershell
   streamlit run app.py
   ```
   The dashboard will automatically open in your default browser at `http://localhost:8501`.

---

### Option B: Linux / macOS Setup (Terminal)

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch application
streamlit run app.py
```

---

### Option C: Jupyter Notebook Execution

To run the complete academic research notebook (`CyberShieldAI_Project.ipynb`):

```bash
# Install jupyter if needed
pip install jupyterlab notebook

# Launch Jupyter
jupyter notebook CyberShieldAI_Project.ipynb
```
Select **Kernel → Restart & Run All** to execute all cells, regenerate benchmark metrics, and display live confusion matrices.

---

### Option D: Running Automated Unit Tests

To run the 20 automated unit tests:

```bash
python -m unittest discover tests -v
```

Expected output:
```text
Ran 20 tests in 0.011s
OK
```

---

## 7. Dataset Details & Academic Transparency

- **File Path**: `data/sample_phishing_dataset.csv`
- **Volume**: 1,000 balanced instances (500 legitimate service archetypes, 500 phishing patterns).
- **Features Extracted**: `url_length`, `dot_count`, `hyphen_count`, `digit_count`, `special_char_count`, `is_ip`, `uses_https`, `is_shortener`, `subdomain_count`, `keyword_count`, `has_at_symbol`, `has_hex_encoding`, `is_punycode`, `domain_entropy`.
- **Academic Disclaimer**: The dataset included in this repository is an **engineered synthetic demonstration dataset** created to enable reproducible offline evaluation and academic defense without exposure to live malware. It should **not** be presented as real-world threat intelligence.
- **External Public Reference Datasets**:
  - [Mendeley Phishing Dataset](https://data.mendeley.com/datasets/c2gw7fy2j4/3)
  - [PhishTank Free Data Feeds](https://phishtank.org/)
  - [University of New Brunswick URL Dataset (ISCX-URL-2016)](https://www.unb.ca/cic/datasets/url-2016.html)

---

## 8. Defensive Scope and Security Boundaries

1. **Non-Intrusive**: CyberShield AI does **not** make HTTP requests, crawl destination pages, resolve live DNS, or execute JavaScript. It inspects strings entirely in-memory.
2. **Privacy Preserving**: No emails, passwords, tokens, or credentials are logged or transmitted externally.
3. **No Offensive Capabilities**: This software contains no exploit payloads, credential harvesting mechanisms, port scanners, or unauthorized network probing modules.

---

## 9. GitHub Publishing Instructions

To publish this project to GitHub for your portfolio and Google Form submission:

```bash
# 1. Initialize git repository (if not already initialized)
git init

# 2. Add all files
git add .

# 3. Commit with a clear descriptive message
git commit -m "feat: CyberShield AI initial academic release with full ML and Streamlit dashboard"

# 4. Link to your GitHub repository
git remote add origin https://github.com/ipsita275/cybershield-ai.git

# 5. Push to GitHub main branch
git branch -M main
git push -u origin main
```

### Recommended GitHub Topics
`python`, `cybersecurity`, `phishing-detection`, `machine-learning`, `streamlit`, `information-security`, `defensive-security`

---

## 10. Required Submission Files Inventory

| Deliverable File | Description | Format |
| :--- | :--- | :--- |
| `CyberShieldAI_Project.ipynb` | Complete analysis notebook with feature extractors, training pipeline, and outputs | Valid Jupyter Notebook (v4 JSON) |
| `requirements.txt` | Complete list of pinned, compatible Python dependencies | Plaintext |
| `YourName_ProjectReport.docx` | Academic project report with all 17 formal sections and styling | Microsoft Word (.docx OpenXML) |
| `Ipsita_ProjectReport.docx` | Academic project report authored for candidate Ipsita | Microsoft Word (.docx OpenXML) |
| `README.md` | Full system overview, execution instructions, and GitHub guide | Markdown |
| `app.py` | Complete runnable Streamlit dashboard application | Python Script |
| `data/sample_phishing_dataset.csv` | Labeled benchmark demonstration dataset | CSV |
| `tests/` | 20 comprehensive unit tests with 100% pass rate | Python unittest |

---

## 11. Author & Acknowledgements

- **Author**: Ipsita
- **System**: CyberShield AI — Intelligent Phishing & URL Threat Detection System
- **Academic Citation**: Developed in accordance with NIST Cybersecurity Framework (CSF 2.0) and OWASP Top 10 guidelines.
#   I p s i t a _ C y b e r S h i e l d A I _ S u b m i s s i o n _ B u n d l e _ o u t e r  
 