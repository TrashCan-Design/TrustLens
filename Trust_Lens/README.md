<p align="center">
  <img src="./trustlens_logo_1776356219500.png" width="128" alt="TrustLens Logo"/>
</p>

# 🛡️ TrustLens: High-Assurance Website Authenticity

**Real-time threat intelligence and authenticity verification for the modern web.**

TrustLens is a professional-grade browser extension (Manifest V3) designed to dismantle sophisticated phishing, domain impersonation, and malicious site techniques. By combining authoritative DNS verification, SSL/TLS inspection, and cross-referenced identity fingerprints, TrustLens provides a definitive **Trust Score** for every website you visit.

---

## 🚀 Key Pillars of Trust

### 1. Infrastructure Integrity
We verify the "plumbing" of the domain to ensure it hasn't been hijacked or misconfigured.
- **Authoritative DNS/SOA Verification:** Cross-references Start of Authority (SOA) and Name Server (NS) records to detect shadow DNS or hijacking.
- **SSL/TLS Deep Scan:** Validates certificate chain, CA trust levels, and differentiates between basic DV (Domain Validated) and high-assurance certificates.
- **DNSSEC & Email Security:** Checks for SPF, DMARC, and MX record sanity to prevent email spoofing vectors.

### 2. Identity & Ownership
Tracing the digital footprint of the website's operators.
- **Advanced Impersonation Detection:** Uses a proprietary scoring model to compare site fingerprints against canonical brand data to flag homograph attacks and typosquatting.
- **RDAP/WHOIS Ownership Tracing:** Analyzes registrant history and cross-references data points to verify organizational legitimacy.
- **Domain Age Analysis:** Identifies newly registered "burner" domains frequently used in tactical phishing campaigns.

### 3. Behavioral Risk Analysis
Real-time integration with global threat intelligence.
- **Google Safe Browsing API:** Instant checks against millions of known malicious URLs.
- **High-Risk TLD (Top-Level Domain) Scoring:** Dynamically penalizes domains on TLDs known for high abuse rates (e.g., `.top`, `.tk`, `.zip`).
- **Structure Analysis:** Scans for suspicious subdomain nesting and deceptive pathing.

---

## 🧠 Advanced Score Engine

The TrustLens **Score Engine** uses a weighted multi-pillar model to calculate a real-time rating from **0 to 100**:

| Component | Weight | Key Metrics |
| :--- | :--- | :--- |
| **Authoritative Verification** | 20% | SOA/NS matching, Impersonation Confidence |
| **Identity & Ownership** | 18% | RDAP verification, Cross-source consistency |
| **DNS & Email Security** | 14% | SPF/DMARC/MX health |
| **Safe Browsing** | 14% | Google Threat Database status |
| **SSL Certificate** | 12% | Encryption strength, CA Trust, Cert Type |
| **Additional Factors** | 22% | Domain Age, TLD Risk, Structural Analysis |

> [!IMPORTANT]
> **Compounding Penalties:** TrustLens doesn't just add up scores. It detects correlations—like a high-risk TLD combined with a young domain and a basic DV certificate—and applies exponential penalties to reflect the true risk level.

---

## 🛠️ Installation

### Developer / Researcher Mode
1. **Clone the repository:**
   ```bash
   git clone https://github.com/TrashCan-Design/TrustLens.git
   ```
2. **Setup Dependencies:**
   ```bash
   npm install
   ```
3. **Load in Browser:**
   - Open Chrome/Edge and go to `chrome://extensions/`.
   - Enable **Developer Mode**.
   - Click **Load unpacked** and select the `Trust_Lens` folder.

---

## 📁 Technical Architecture

- **`manifest.json`**: Chrome Extension Manifest V3.
- **`background.js`**: Core service worker facilitating high-concurrency API requests and caching.
- **`utils/`**: Specialized modules for DNS, SSL, and Identity verification.
- **`popup.js/html/css`**: A premium, glassmorphic UI for real-time risk visualization.
- **`options.js/html/css`**: Centralized configuration for API keys and advanced scan modes.

---

## 🛡️ Privacy & Security
TrustLens is built with a **Privacy-First** approach. Most scans are performed against public DNS and threat databases. We do not track user browsing history beyond the active analysis required for the Trust Score.

---

<p align="center">
  Built for <b>Research Methodology</b> • 2026
</p>
