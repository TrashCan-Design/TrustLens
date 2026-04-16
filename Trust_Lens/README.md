# TrustLens

**Real-time website authenticity and trust analysis — SSL, DNS, domain age, safe browsing and more.**

TrustLens is a Chrome/Edge (Manifest V3) browser extension designed to protect users by analyzing the trustworthiness of websites in real-time. It evaluates multiple factors to generate a comprehensive trust score, letting you know whether a site is safe to browse or potentially malicious.

## Features ✨
- **Live Connectivity Check:** Ensures the website and its servers are properly reachable.
- **SSL/TLS Validation:** Checks the security of a domain's certificate.
- **DNS Analysis:** Validates the domain name mapping for red flags.
- **Domain Structure & TLD Risk:** Identifies high-risk Top-Level Domains and spoofing attempts.
- **Domain Age Calculation:** Flags newly-registered, suspicious domains.
- **Google Safe Browsing Integration:** Verifies against Google's known malicious URLs list.
- **Dark Mode Dashboard:** A beautiful, intuitive, and modern popup interface to quickly digest risk scores.
- **Configurable Options:** Access advanced capabilities such as setting API keys and scanning modes.

## Installation 🚀
### Loading Locally for Development
1. Clone the repository: `git clone https://github.com/Pawan-Punjabi/Trust_Lens.git`
2. Open Chrome/Edge and navigate to the Extensions page (`chrome://extensions/` or `edge://extensions/`).
3. Enable **Developer Mode** in the top right corner.
4. Click **Load unpacked** and select the directory containing the project files.

## Project Structure 📁
- `manifest.json`: Web Extension manifest (v3).
- `background.js`: Service worker managing background processes, API requests, and caching.
- `content.js`: Handles communication with the web pages.
- `popup.html` / `popup.js` / `popup.css`: User Interface for live extension popup.
- `options.html` / `options.js` / `options.css`: Settings page for user customizations (e.g., API key config).
- `utils/`: Core algorithms and utilities performing the specific health/authenticity checks (DNS, TLD checking, SafeBrowsing, Score Engine, etc.).

## Permissions
- `activeTab`: To analyze the site you are currently visiting.
- `tabs`: To access information across browsing tabs.
- `storage`: To save extension options and cached data securely.
- `webRequest`: Required for intercepting connections to analyze security context.
- `dns` (optional): Deep-dive domain name resolution inspection.
