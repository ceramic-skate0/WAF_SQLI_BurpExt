# WAF Oracle Studio

[![Burp Suite](https://shields.io)](https://portswigger.net)
[![Language](https://shields.io)](https://jython.org)
[![License](https://shields.io)](LICENSE)

An automated, behavior-driven Burp Suite extension designed to identify vulnerabilities by weaponizing WAF handling states. Instead of relying on traditional web-application response anomalies, **WAF Oracle Studio** treats edge-protection layers (such as Akamai and Azure WAF) as an evaluation oracle. It detects injections by contrasting deterministic firewall blocking states against uninhibited origin application flows.

---

## 💾 Installation & Setup

### Prerequisites
* **Burp Suite Professional / Community Edition**
* **Jython Standalone JAR** (v2.7.x recommended for Burp Python extensions)

### Step-by-Step Download & Load
1. **Download the Extension**: Clone this repository or download the latest release ZIP package directly:
   ```bash
   git clone https://github.com
   ```
2. **Configure Burp Python Environment** *(Skip if already done)*:
   * Open Burp Suite $\rightarrow$ **Extensions** $\rightarrow$ **Extension settings**.
   * Under **Python environment**, click **Select file** next to **Location of Jython standalone JAR file** and select your downloaded Jython JAR.
3. **Load the Extension**:
   * Navigate to **Extensions** $\rightarrow$ **Installed**.
   * Click **Add**.
   * Set **Extension type** to **Python**.
   * Select `WAF_SQLI.py` as the **Extension file** path.
   * Click **Next**. The console will log successful initialization, and a new **WAF Oracle Studio** tab will appear in your top menu bar.

---

## 📐 Detection Methodology

The framework evaluates parameters via paired validation probes to eliminate dynamic application layout noise:

1. **True Assertion Probe**: Appends an explicit signature injection payload designed to reliably trip signature filters at the edge proxy layer.
2. **False Assertion Probe**: Appends an equivalent alternate mutation string structurally designed to skip ruleset traps and hit the origin application container directly.
3. **Oracle Classification**: If the True payload receives a designated block status configuration value (e.g., `403`), while the False payload clears the edge cleanly, a flaw is verified and flagged directly in your native Burp Issue tracker.

---

## ⚙️ Custom Configuration

You can easily modify the script constants at the top of `WAF_SQLI.py` to match the behavior profiles of your specific targets before loading:

```python
# Threshold configuration for the Decision Oracle
WAF_BLOCK_CODES = [403, 406, 429]      # Status codes returned when WAF blocks a request
SUCCESS_PASS_CODES = [200, 301, 302]   # Status codes returned when the request reaches the origin
```

---

## 🤝 Contributing

Contributions, bug reports, and payload additions are welcome! 
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

``
sqlmap -u "https://example.com" 
  --code=200 
  --technique=B 
  --test-filter="Boolean-based blind - Parameter replace" 
  --skip-heuristics 
  --no-cast 
  --batch 
  --flush-session
``
