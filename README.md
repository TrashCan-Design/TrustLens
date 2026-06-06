<p align="center">
  <img src="./trustlens_logo_1776356219500.png" width="120" alt="TrustLens Logo" />
</p>

<h1 align="center">TrustLens</h1>

<p align="center">
  <strong>Real-time website trust and authenticity analysis for the modern web.</strong><br/>
  A Manifest V3 browser extension that scores every site you visit across 11 independent security dimensions.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Manifest-V3-4285F4?style=flat-square&logo=googlechrome&logoColor=white" alt="MV3"/>
  <img src="https://img.shields.io/badge/Version-1.1.0-00e5ff?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Chrome%20%7C%20Edge-blue?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square" alt="PRs Welcome"/>
</p>

---

## 📖 What is TrustLens?

Every time you land on a website, dozens of signals quietly determine whether you're looking at the real thing or a sophisticated clone designed to steal your credentials or data. Certificate authorities issue free SSL certs to anyone. Domain registrars sell `.xyz` addresses for pennies. Typosquatters register near-identical domains and wait for a mistyped URL.

**TrustLens** cuts through this noise. It is a browser extension that runs a comprehensive, multi-layered trust analysis on the active tab — in real time — and surfaces a single, weighted **Trust Score** between 0 and 100. The score is not a simple checklist; it's the output of a cross-correlated signal engine that escalates risk when weak signals appear together, reflecting how real-world phishing attacks actually work.

This project was built to explore how public DNS infrastructure, certificate metadata, and RDAP ownership data can be composed into a practical, client-side threat intelligence tool — with zero telemetry and no dependency on a proprietary backend.

> [!NOTE]
> TrustLens is an educational and research tool. It is designed to surface publicly available information about a domain's infrastructure. It does not perform any active probing, send traffic to the target site, or store your browsing history.

---

## 🎓 Educational Overview

Understanding what TrustLens checks requires a brief look at the attack surface it's trying to cover:

- **Phishing** relies on visual similarity — a site that *looks* legitimate but is hosted on a different domain. Detecting this requires comparing the suspected domain's infrastructure fingerprint against the real brand's known infrastructure.
- **Homograph attacks** use Unicode characters that look identical to ASCII ones (e.g., Cyrillic `а` vs. Latin `a`) to register lookalike domains that pass casual visual inspection.
- **Typosquatting** registers domains with common misspellings (`gooogle.com`, `paypa1.com`) and relies on muscle memory to drive traffic.
- **TLD abuse** exploits cheap or free top-level domains (`.tk`, `.zip`, `.xyz`) that have historically high abuse rates and low registration barriers.

TrustLens addresses all of these vectors without ever contacting the suspicious site directly. Instead, it queries authoritative DNS infrastructure, RDAP registration databases, and Google's public threat feeds to build a picture of the domain's trustworthiness from the outside in.

---

## ✨ Key Features

### 🔒 Authoritative DNS Verification
TrustLens fetches the SOA (Start of Authority) and NS (Name Server) records for a domain and cross-references them for consistency. A mismatch between the SOA primary server and the declared nameservers is a known indicator of DNS misconfiguration or hijacking. It also identifies the hosting provider from the nameserver patterns, which adds a layer of context to the overall verdict.

### 🕵️ Impersonation & Brand Detection
The extension maintains a curated registry of ~80 well-known brands alongside their canonical domains. When a visited hostname contains a brand keyword or closely resembles one (via Levenshtein distance ≤ 2 or common character substitutions like `0→o`, `1→l`), TrustLens fetches live DNS fingerprints for both the visited and canonical domains and compares them across IP addresses, nameservers, registrant organization, SOA records, and domain age. Each mismatch contributes to an **Impersonation Confidence Score**; a score above 50 locks the final trust rating well below 20.

### 🛡️ SSL/TLS Deep Inspection
Rather than simply checking for HTTPS, TrustLens inspects the certificate itself — the issuing CA, its trust tier, the certificate type (DV/OV/EV), expiry, SAN count, and whether the cert was issued within the last 7 days. A Domain Validated certificate on a high-risk TLD means almost nothing; the score engine degrades the SSL component accordingly.

### 📧 Email Authentication (SPF / DMARC)
A domain's email security posture is a strong proxy for organizational maturity. TrustLens checks for the presence and strictness of SPF (`-all` vs `~all` vs `+all`) and DMARC records (`reject` vs `quarantine` vs `none`) via Google's DNS-over-HTTPS resolver. Missing or weak email authentication records lower the identity consistency score.

### 🌍 RDAP Ownership Tracing
Using the [RDAP protocol](https://rdap.org), TrustLens retrieves structured registration data for a domain — registrant organization, registrar, registration date, country, and EPP status codes. It checks for dangerous statuses like `serverHold` or `pendingDelete`, and awards positive signals for active transfer-lock flags. RDAP data is the authoritative source for domain ownership; missing data is itself a risk signal.

### 📅 Domain Age Analysis
Newly registered domains are disproportionately used in phishing campaigns because attackers burn through them quickly. TrustLens calculates the domain age from RDAP registration events, applying escalating penalties for domains under 30 days (fail), under 6 months (warn), and compounding that against other risk signals.

### 🎯 TLD Risk Classification
The extension ships with a hand-curated list of over 100 high-risk TLDs, ~30 moderate-risk TLDs, and a broad set of trusted ccTLDs and gTLDs. The TLD risk class is one of the most powerful caps in the scoring system — a domain on a genuinely high-risk TLD cannot score above 45, regardless of how many other checks pass.

### 🔴 Google Safe Browsing Integration
When a user configures their own Safe Browsing API key, TrustLens checks the active URL against Google's v4 threat database, covering malware, social engineering, unwanted software, and potentially harmful applications. A positive match caps the trust score at 15.

### 🧩 Domain Structure Analysis
The extension analyzes the structural composition of the hostname — subdomain depth, embedded brand names in subdomains, Punycode / IDN presence, mixed Unicode scripts, excessive hyphenation, and numeric subdomain patterns. A domain like `secure.login.paypal.account-verify.xyz` raises multiple structure flags independently of any other check.

---

## 🧠 The Score Engine

The score engine is the core of TrustLens and deserves its own explanation. It is not a simple weighted average.

Each of the 8 weighted modules contributes points on a `pass / warn / fail / skip` scale — with `warn` worth 35% of the module's weight and `skip` worth 20% (a conservative partial credit for modules that couldn't run). The raw weighted score then goes through a series of **cross-module escalations** before the final caps are applied.

### Cross-Module Escalations

The escalation logic is the key insight: individual weak signals are often insufficient to flag a site, but the *combination* of signals is far more telling.

- A high-risk TLD + a young/unverified domain → the domain structure module is escalated from `pass` to `warn`
- A high-risk TLD + weak identity data → identity escalated from `warn` to `fail`
- DNS failure + weak identity → identity escalated to `fail`
- Impersonation detected + a DV cert → SSL downgraded from `pass` to `warn` (DV certs are trivially obtained, even by phishing sites)
- Failed Safe Browsing check → score hard-capped at 15
- Unverified `.gov` claim → score hard-capped at 15
- Impersonation confidence ≥ 70% → score hard-capped at 10

### Accumulative Penalties

Beyond escalations, the engine applies accumulative penalties for clusters of weak signals — each additional `warn` module beyond the first costs 4 points, each additional `fail` costs 6, and a mix of both applies an extra 8-point penalty. This prevents an attacker from "passing" several minor checks to scrape above a safe-looking threshold.

### Score Bands

| Score | Band | Ring Color |
|:---:|:---|:---|
| 80 – 100 | ✅ Trusted | Cyan `#00e5ff` |
| 60 – 79 | 🟦 Moderate | Teal `#4dd0e1` |
| 40 – 59 | ⚠️ Caution | Amber `#ffb300` |
| 20 – 39 | 🟠 Risky | Orange `#ff7043` |
| 0 – 19 | 🔴 Dangerous | Red `#ff3b3b` |

---

## 🛠️ Technology Stack

TrustLens is intentionally dependency-light. The entire analysis pipeline runs as vanilla JavaScript in the browser, without a backend server or a bundler.

| Layer | Technology |
|:---|:---|
| Extension Platform | Chrome Extensions — Manifest V3 |
| Background Runtime | Service Worker (ES Module) |
| DNS Resolution | Google DNS-over-HTTPS (`dns.google/resolve`) |
| Domain Registration | RDAP (`rdap.org`, Verisign fallback) |
| Threat Intelligence | Google Safe Browsing API v4 |
| UI | Vanilla HTML + CSS (glassmorphism, SVG ring gauge) |
| Storage | `chrome.storage.sync` (API keys, onboarding state) |

---

## 📦 Installation

### Load as an Unpacked Extension (Developer Mode)

This is the recommended approach for local testing and development.

**1. Clone the repository**
```bash
git clone https://github.com/TrashCan-Design/TrustLens.git
cd TrustLens/Trust_Lens
```

**2. Install dependencies** *(optional — only needed for the icon generation script)*
```bash
npm install
```

**3. Load the extension in Chrome or Edge**
- Navigate to `chrome://extensions/`
- Enable **Developer Mode** (toggle in the top-right)
- Click **Load unpacked** and select the `Trust_Lens` directory

The TrustLens icon will appear in your browser toolbar immediately. Click it on any website to run a scan.

---

## 🚀 Usage

### Running a Scan
Navigate to any website and click the TrustLens toolbar icon. The extension will automatically begin a full scan and display the animated Trust Score ring within a few seconds.

### Reading the Results
Each of the 11 module cards can be expanded by clicking its header. The detail line explains the verdict in plain English, and the raw data block shows the exact values retrieved from DNS, RDAP, and the certificate — so you can verify the source yourself.

### Copying a Report
The **Copy Report** button in the popup generates a plain-text summary of the scan, formatted for easy sharing or logging.

### Configuring the Safe Browsing API Key
TrustLens does not ship with an API key for Google Safe Browsing. To enable that module:

1. Get a free API key from the [Google Cloud Console](https://console.cloud.google.com/) (Safe Browsing API).
2. Open the TrustLens **Options** page (right-click the icon → Options, or via `chrome://extensions/`).
3. Paste your key into the Safe Browsing field and save.

---

## 🗂️ Project Structure

```
Trust_Lens/
├── manifest.json           # MV3 extension manifest
├── background.js           # Service worker — scan orchestration & caching
├── content.js              # Content script — page metadata extraction
├── popup.html              # Extension popup UI
├── popup.js                # Popup controller — rendering, scan dispatch
├── popup.css               # Glassmorphic UI styles
├── options.html            # Settings page UI
├── options.js              # Settings page logic
├── options.css             # Settings page styles
└── utils/
    ├── authoritativeLookup.js  # SOA/NS verification + brand impersonation engine
    ├── certificate.js          # SSL/TLS inspection + domain structure analysis
    ├── dns.js                  # DNS & email security (SPF, DMARC, MX, CAA)
    ├── domainAge.js            # RDAP-based domain age check
    ├── identity.js             # Ownership tracing (RDAP + DNS cross-reference)
    ├── safeBrowsing.js         # Google Safe Browsing API integration
    ├── scoreEngine.js          # Weighted scoring, escalation logic, band assignment
    └── tldCheck.js             # TLD risk classification
```

---

## ⚙️ Configuration

TrustLens stores its configuration in `chrome.storage.sync`, which means settings follow the user across devices when signed into Chrome.

| Setting | Description | Default |
|:---|:---|:---|
| `safeBrowsingKey` | Google Safe Browsing API v4 key | *(empty — module skipped)* |
| `hasSeenOnboarding` | Whether the first-run overlay has been dismissed | `false` |

All configuration is managed through the **Options** page. No manual file editing is required.

---

## 🔬 How It Works Internally

When you click the TrustLens icon, the popup sends a `SCAN` message to the background service worker, which acts as the orchestration layer. The service worker fans out the analysis across all utility modules in parallel using `Promise.all`, waits for all results, then passes them to the score engine.

The score engine receives the raw module results, runs the cross-module escalation logic, computes the weighted score, applies penalties and caps, and returns a final `{ score, band, color, impersonationDetected }` object. The popup receives this response and animates the SVG ring gauge to the final score.

DNS queries are routed through Google's DNS-over-HTTPS endpoint (`https://dns.google/resolve`) rather than the system resolver. This matters because local DNS resolvers can be poisoned or may return cached/malformed responses; DoH queries are authenticated and bypass local network manipulation.

RDAP lookups go to `rdap.org` with a fallback to Verisign's endpoint for `.com` domains. RDAP is the modern successor to WHOIS and returns structured JSON rather than free-text, which makes parsing reliable across registrars.

The impersonation engine computes a Levenshtein distance between the visited domain root and every brand name in its registry. If the distance is ≤ 2 (or a homoglyph substitution matches), it fetches live DNS fingerprints for both the visited domain and the canonical brand domain and compares IP addresses, nameservers, registrant organizations, SOA records, and domain age. Each discrepancy contributes to an impersonation confidence score that's used both to generate a human-readable alert and to cap the final trust score.

---

## 🧭 Ethical & Educational Disclaimer

TrustLens is built for **educational and research purposes**. All analysis is performed using publicly available information from authoritative DNS infrastructure, RDAP databases, and Google's threat intelligence feeds. The extension does not send any requests to the websites it analyzes, does not store browsing history, and does not exfiltrate any data.

The impersonation detection engine is designed to *alert users*, not to make definitive legal or security judgments. A warning from TrustLens should be treated as a prompt for careful verification, not as a conclusive verdict. False positives are possible, particularly for newly registered legitimate domains or domains with minimal DNS infrastructure.

---

## 🤝 Contributing

Contributions are welcome. If you want to improve the TLD risk lists, add new detection heuristics, improve the UI, or fix a bug, here's how to get started:

1. Fork the repository and create a feature branch (`git checkout -b feature/my-improvement`)
2. Make your changes and test them by loading the extension as unpacked in Chrome
3. Open a pull request with a clear description of what you changed and why

For significant changes — particularly to the scoring weights or escalation logic — please open an issue first to discuss the approach. The score engine has been calibrated carefully; changes should be backed by reasoning.

If you discover a false positive or false negative on a real-world domain, opening an issue with the domain and what TrustLens reported is extremely helpful for calibration.

---

## 📄 License

This project is licensed under the **MIT License**. See [`LICENSE`](./LICENSE) for details.

---

## 🙏 Acknowledgments

- [**Google Safe Browsing API**](https://developers.google.com/safe-browsing) — the threat intelligence backbone for the `sb` module
- [**rdap.org**](https://rdap.org) — a public RDAP aggregation service that simplifies cross-registrar domain lookups  
- [**Google DNS-over-HTTPS**](https://developers.google.com/speed/public-dns/docs/doh) — authenticated, privacy-preserving DNS resolution
- The broader security research community whose published work on phishing detection, typosquatting, and domain abuse informed the design of this engine

---

<div align="center">

**⭐ Star this repo if you find it helpful for your educational pursuits!**

Made with ❤️ by [Jay](https://www.linkedin.com/in/jayshah-cybersec/)

</div>
