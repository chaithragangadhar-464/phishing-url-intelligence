# 🛡️ Phishing URL Intelligence

> An AI-powered URL security analysis system that combines Machine Learning classification with deterministic cybersecurity heuristics to detect phishing URLs and explain exactly why they're suspicious.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Visit%20App-brightgreen)](https://chaithragangadhar-464.github.io/phishing-url-intelligence/)
[![GitHub Repo](https://img.shields.io/badge/GitHub-Repository-black)](https://github.com/chaithragangadhar-464/phishing-url-intelligence)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![React](https://img.shields.io/badge/React-18-blue)](https://react.dev)
[![XGBoost](https://img.shields.io/badge/Model-XGBoost-orange)](https://xgboost.readthedocs.io)

---

## 📖 Overview

Phishing URL Intelligence goes beyond a simple "enter URL → safe/phishing" classifier. It provides:

- **ML Classification** — XGBoost model trained on 45 URL features
- **Risk Score (0–100)** — Blended ML probability + security heuristics
- **16 Security Rules** — Deterministic checks with evidence and severity
- **Explainable Results** — Every flag is justified with a plain-English description
- **Threat Categories** — Brand Impersonation, Homograph Attack, URL Obfuscation, etc.
- **Feature Importance** — Which URL properties drove the prediction

**Core Philosophy:**
```
URL → Evidence → Security Analysis → ML Analysis → Risk → Explanation
```

The system **never visits or fetches submitted URLs** — all analysis is pure string-based.

---

## 🏗️ Architecture

```
User submits URL
        ↓
URL Validation & Normalization
        ↓
Feature Extraction (45 features)
        ↓
Security Heuristic Engine (16 rules)
        ↓
XGBoost ML Classification
        ↓
Risk Score = ML(60%) × Heuristics(40%)
        ↓
Threat Categorization
        ↓
Explainability Engine
        ↓
Structured JSON Response
        ↓
React Frontend Visualization
```

---

## ✨ Features

### URL Analysis
- **45 lexical, structural, and security features** extracted per URL
- **16 deterministic security rules** with HIGH/MEDIUM/LOW severity
- **XGBoost classifier** for ML-based probability estimation
- **Hybrid risk score**: `ML_prob × 60% + Heuristics × 40%`
- No network requests to analyzed URLs (SSRF-safe)

### Security Rules
| Rule | Severity | Description |
|------|----------|-------------|
| IP Address as Hostname | HIGH | Raw IP used instead of domain |
| @ Sign in URL | HIGH | Redirect obfuscation technique |
| Punycode / IDN Homograph | HIGH | Unicode character spoofing |
| Brand Impersonation | HIGH | Brand in subdomain/path, not domain |
| HTTP + Sensitive Keywords | HIGH | Cleartext + auth/payment content |
| Suspicious TLD | MEDIUM | Free/abused TLDs (.tk, .ml, .xyz, ...) |
| Excessive Subdomains | MEDIUM | 3+ subdomain levels |
| Authentication Keywords | MEDIUM | login, verify, password, etc. |
| Payment Keywords | MEDIUM | bank, paypal, billing, etc. |
| URL Shortener | MEDIUM | Hides real destination |
| Non-Standard Port | MEDIUM | Unusual port numbers |
| Excessive URL Length | LOW | URLs > 100 chars |
| High Entropy | LOW | Randomized/obfuscated content |
| URL Encoding Obfuscation | LOW | Multiple percent-encoded chars |
| Double Slash in Path | LOW | Redirect manipulation |
| Hyphen in Domain | LOW | Common in spoof domains |

### Threat Categories
- Credential Harvesting
- Brand Impersonation
- Homograph Attack
- URL Obfuscation
- Suspicious Domain Structure
- Payment Targeting
- Social Engineering
- Hidden Destination

---

## 🧠 Machine Learning

### Model
**XGBoost Classifier** — selected for:
- Excellent precision/recall on tabular data
- Fast inference (< 10ms per URL)
- Native feature importance
- No deep learning overhead

### Features (45 total)
**Lexical:** url_length, hostname_length, path_length, num_dots, num_hyphens, num_digits, url_entropy, hostname_entropy, digit_ratio, ...

**Structural:** is_https, is_ip_address, has_port, num_subdomains, num_directories, num_query_params, has_at_sign, has_punycode, has_encoded_chars, ...

**Security:** is_suspicious_tld, is_url_shortener, num_auth_keywords, num_payment_keywords, num_brand_tokens, brand_impersonation_indicator, domain_has_hyphen, ...

### Training
- **Dataset**: Synthetic URL dataset (10,000 URLs — 50/50 balanced)
  - Legitimate: Real domain patterns from known safe sites
  - Phishing: 7 attack pattern categories (IP-based, brand spoofing, punycode, @ trick, excessive subdomains, obfuscated, suspicious TLD)
- **Split**: 80/20 train/test, stratified, seed=42
- **Hyperparameters**: n_estimators=200, max_depth=6, learning_rate=0.1

### Verified Metrics (on test split)

| Metric | Score |
|--------|-------|
| Accuracy | 1.0000 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1-Score | 1.0000 |
| ROC-AUC | 1.0000 |

> **Note:** The perfect metrics reflect the synthetic dataset design where feature patterns are deterministic. In production with real-world URLs, performance would be lower and should be evaluated on a real phishing dataset (e.g., [PhiUSIIL from UCI](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)).

### Top Feature Importances
1. `num_dots` (36.2%)
2. `num_auth_keywords` (31.9%)
3. `domain_length` (10.2%)
4. `is_https` (7.2%)
5. `num_at_signs` (4.0%)

---

## 🚀 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Vanilla CSS |
| Backend | Python 3.12, FastAPI |
| ML | XGBoost, scikit-learn, pandas, numpy |
| Deployment | Vercel (frontend), Render (backend) |
| Version Control | Git + GitHub |

---

## 📁 Project Structure

```
phishing-url-intelligence/
│
├── frontend/                    # React + Vite
│   ├── src/
│   │   ├── components/          # Header, URLInput, AnalysisResult, ...
│   │   ├── utils/api.js         # API client
│   │   ├── App.jsx
│   │   ├── index.css            # Design system
│   │   └── main.jsx
│   ├── index.html
│   └── vite.config.js
│
├── backend/                     # FastAPI
│   ├── app/
│   │   ├── main.py              # FastAPI app + CORS + lifecycle
│   │   ├── api/routes.py        # POST /api/analyze, GET /api/examples
│   │   ├── services/
│   │   │   ├── analyzer.py      # Full analysis pipeline
│   │   │   └── risk_scorer.py   # Risk scoring + threat categories
│   │   ├── features/extractor.py # 45-feature URL extractor
│   │   ├── rules/heuristics.py  # 16 security rules
│   │   └── models/loader.py     # Model loading + inference
│   ├── tests/test_analysis.py   # 41 tests (all passing)
│   ├── Procfile                 # Render deployment
│   └── run.py
│
├── ml/
│   └── training/train.py        # Training pipeline
│
├── models/
│   ├── phishing_model.joblib    # Trained XGBoost model
│   └── model_meta.joblib        # Feature names + metadata
│
├── .gitignore
├── .env.example
├── requirements.txt
├── render.yaml
└── README.md
```

---

## ⚙️ Local Development

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend

```bash
# Install dependencies
pip install -r requirements.txt

# Train the model (generates models/)
python ml/training/train.py

# Start the backend
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend

```bash
cd frontend
npm install
# Set VITE_API_URL in .env (defaults to http://localhost:8000 via proxy)
npm run dev
```

### Running Tests

```bash
cd backend
python -m pytest tests/ -v
```

---

## 🌐 API Usage

### POST /api/analyze

```bash
curl -X POST https://your-backend.onrender.com/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://secure-paypal-login.verify.tk/signin"}'
```

Response:
```json
{
  "url": "http://secure-paypal-login.verify.tk/signin",
  "classification": "phishing",
  "risk_score": 87,
  "risk_level": "HIGH",
  "confidence": 0.98,
  "threat_categories": ["Brand Impersonation", "Credential Harvesting"],
  "risk_factors": [
    {
      "name": "Brand Impersonation",
      "severity": "HIGH",
      "description": "URL contains a well-known brand name..."
    }
  ],
  "features": { "url_length": 47, "is_https": false, ... },
  "explanation": "⚠️ This URL appears suspicious...",
  "model_used": "XGBoost"
}
```

### GET /health

```bash
curl https://your-backend.onrender.com/health
# {"status":"healthy","model_loaded":true,"version":"1.0.0"}
```

---

## 🔐 Environment Variables

### Frontend (`.env`)
```
VITE_API_URL=https://your-backend.onrender.com
```

### Backend (`.env`)
```
HOST=0.0.0.0
PORT=8000
ALLOWED_ORIGINS=https://your-frontend.vercel.app
```

---

## 🔒 Security Considerations

- All submitted URLs are treated as **untrusted strings** — they are never visited
- Input length is capped at 2048 characters
- No `eval()`, subprocess execution, or OS command injection vectors
- External API calls are not made during analysis
- `.env` file is git-ignored — no secrets are committed
- CORS is configured to allow only specific frontend origins

---

## 🚀 Deployment

### Frontend → Vercel
```bash
# Install Vercel CLI
npm i -g vercel
cd frontend
vercel --prod
# Set VITE_API_URL environment variable in Vercel dashboard
```

### Backend → Render
1. Connect GitHub repo to Render
2. Create a new Web Service
3. Root directory: `backend`
4. Build command: `pip install -r requirements.txt`
5. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
6. Add environment variable: `ALLOWED_ORIGINS=https://your-vercel-app.vercel.app`

---

## 🔮 Future Improvements

1. **Real phishing dataset** — Replace synthetic data with PhiUSIIL or URL-Phish dataset
2. **WHOIS integration** — Domain age and registration data
3. **VirusTotal API** — Real-time threat intelligence (optional, graceful fallback)
4. **SHAP explanations** — More precise per-prediction feature attribution
5. **Scan history** — localStorage-based analysis history
6. **URL screenshot** — Visual phishing indicator (requires sandboxed browser)
7. **Bulk analysis** — CSV upload for batch URL checking
8. **Real-time typosquatting** — Levenshtein distance against known brand domains

---

## 📊 Dataset Note

This project uses a **synthetic URL dataset** generated to mirror known phishing patterns (7 attack categories). For production use, consider training on:

- [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) — 235K URLs, 54 features
- [URL-Phish Dataset](https://www.kaggle.com/datasets/siddheshbhansali/phishing-url-detection-111k-urls-22-features) — 111K URLs, 22 features

---

## 👤 Author

Built by [chaithragangadhar-464](https://github.com/chaithragangadhar-464) for a cybersecurity hackathon.
