# 🔍 Multi-Source Information Gathering Tool (OSINT Recon Tool)

A professional-grade, modular Python-based network intelligence tool that automates reconnaissance tasks including IP geolocation, DNS lookup, SSL certificate inspection, port scanning, and WHOIS analysis.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## ✨ Features

| Module | Description |
|---|---|
| **IP Intelligence** | Fetch public IP details (location, ISP, country, coordinates) using ip-api.com |
| **DNS Lookup** | Retrieve domain records (A, AAAA, MX, NS, TXT, CNAME) |
| **Port Scanner** | Concurrent TCP scan of 19 common ports using multithreading |
| **SSL Certificate** | Extract certificate issuer, expiry date, validity, and SANs |
| **WHOIS Lookup** | Get domain registration details (registrar, dates, name servers) |

### 🔧 Technical Highlights

- **Concurrent scanning** using Python `threading` / `ThreadPoolExecutor` — improves port scan performance by up to 100×
- **Modular architecture** — each feature is an independent, testable module
- **Colored CLI output** with `colorama` for professional terminal UX
- **Comprehensive logging** to both file and console
- **Execution timing** for every operation
- **Robust error handling** with graceful fallbacks

---

## 📁 Project Structure

```
osint-recon-tool/
├── main.py                  # CLI entry point & menu system
├── requirements.txt         # Python dependencies
├── README.md
├── modules/
│   ├── __init__.py
│   ├── ip_lookup.py         # IP geolocation via ip-api.com
│   ├── dns_lookup.py        # DNS record resolution
│   ├── port_scanner.py      # Multithreaded TCP port scanner
│   ├── ssl_checker.py       # SSL/TLS certificate analysis
│   └── whois_lookup.py      # WHOIS domain registration lookup
└── utils/
    ├── __init__.py
    └── helpers.py            # Validation, colored output, logging
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** (uses `X | Y` union type syntax)
- **pip** package manager

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/osint-recon-tool.git
cd osint-recon-tool

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the Tool

```bash
python main.py
```

You'll see a banner and be prompted to:
1. Enter a target domain or IP address
2. Select an operation from the menu
3. View the results with colored output and execution time

---

## 📖 Usage Example

```
  ╔══════════════════════════════════════════════════════════════╗
  ║   OSINT — Multi-Source Information Gathering Tool            ║
  ╚══════════════════════════════════════════════════════════════╝

  Enter target (domain or IP): google.com

  ──────────────────────────────────────────────────
    Select an Operation:
  ──────────────────────────────────────────────────
  [1]  IP Intelligence Lookup
  [2]  DNS Record Lookup
  [3]  Port Scanner
  [4]  SSL Certificate Analysis
  [5]  WHOIS Domain Lookup
  [6]  Run ALL Scans
  [0]  Exit
  ──────────────────────────────────────────────────

  Your choice ▶ 6
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP requests for IP geolocation API |
| `colorama` | Cross-platform colored terminal output |
| `python-whois` | WHOIS domain registration queries |
| `dnspython` | Advanced DNS record resolution |

All dependencies are listed in `requirements.txt`.

---

## 🏗️ Architecture

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  main.py │────▶│   modules/   │────▶│   utils/     │
│  (CLI)   │     │  ip_lookup   │     │  helpers.py  │
│          │     │  dns_lookup  │     │  (validation │
│          │     │  port_scanner│     │   logging    │
│          │     │  ssl_checker │     │   output)    │
│          │     │  whois_lookup│     │              │
└──────────┘     └──────────────┘     └──────────────┘
```

- **`main.py`** — Interactive CLI loop with menu, timing, and session management
- **`modules/`** — Each module is a self-contained class with a single public method (`lookup()`, `scan()`, or `check()`)
- **`utils/helpers.py`** — Shared validation functions, colored output helpers, and logging configuration

---

## 🔮 Future Improvements

1. **Async I/O** — Replace `threading` with `asyncio` + `aiohttp` for even higher concurrency
2. **JSON/CSV Export** — Save results in structured formats for reporting
3. **Shodan API Integration** — Leverage Shodan for deeper host intelligence
4. **Subdomain Enumeration** — Discover subdomains via wordlist or certificate transparency logs
5. **HTTP Header Analysis** — Inspect security headers (HSTS, CSP, X-Frame-Options)
6. **Web Fingerprinting** — Detect web server, CMS, and framework technologies
7. **Rate Limiting** — Add configurable request throttling for stealth
8. **CLI Arguments** — Support `argparse` for non-interactive batch mode
9. **Database Logging** — Store results in SQLite for historical analysis
10. **Docker Support** — Containerized deployment for consistent environments

---

## ⚠️ Disclaimer

This tool is intended for **authorized security research and educational purposes only**. Always obtain proper authorization before scanning systems you do not own. Unauthorized scanning may violate laws and regulations.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
