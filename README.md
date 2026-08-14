# ShieldMori — Threat Intelligence Scanner

<div align="center">

![ShieldMori Banner](https://img.shields.io/badge/ShieldMori-Threat%20Intelligence-C9292B?style=for-the-badge&logo=shield&logoColor=white)

[![VirusTotal](https://img.shields.io/badge/Powered%20by-VirusTotal-394EFF?style=flat-square&logo=virustotal&logoColor=white)](https://www.virustotal.com)
[![Engines](https://img.shields.io/badge/Engines-70%2B%20Antivirus-1a7a4a?style=flat-square)](https://www.virustotal.com)
[![License](https://img.shields.io/badge/License-MIT-888?style=flat-square)](LICENSE)
[![Made by](https://img.shields.io/badge/Made%20by-@YukiiKazunomiya-141414?style=flat-square&logo=github)](https://github.com/YukiiKazunomiya)

**A clean, premium threat intelligence scanner frontend — powered by the VirusTotal API.**  
Scan URLs, domains, IP addresses, file hashes, and files with 70+ antivirus engines in real time.

[Live Demo](#) · [Report Bug](https://github.com/YukiiKazunomiya/shieldmori/issues) · [Request Feature](https://github.com/YukiiKazunomiya/shieldmori/issues)

</div>

---

## Features

- **URL Scanner** — Detect phishing, malware, and malicious redirects in any link
- **Domain Scanner** — Analyze domain reputation and historical threat data
- **IP Address Scanner** — Investigate geolocation, ISP info, and abuse records
- **File Hash Lookup** — Query MD5, SHA-1, or SHA-256 against the VirusTotal database
- **File Upload** — Submit files up to 32MB for deep multi-engine analysis
- **Real-time Terminal Log** — Live scan progress log with color-coded output
- **Engine Result Viewer** — Browse all 70+ engine verdicts with filtering (All / Flagged / Clean)
- **Threat Gauge** — Visual semicircle gauge showing detection percentage
- **No Data Storage** — Files and scan targets are never stored server-side

---

## Tech Stack

| Layer     | Technology                        |
|-----------|-----------------------------------|
| Frontend  | Vanilla HTML · CSS · JavaScript   |
| Fonts     | Bricolage Grotesque · IBM Plex Mono · IBM Plex Sans (Google Fonts) |
| Icons     | Inline SVG (Lucide-style)         |
| API       | [VirusTotal Public API v3](https://developers.virustotal.com/reference/overview) |
| Backend   | Any server (Node.js, Python, etc.) that proxies VT API calls |

---

## Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/YukiiKazunomiya/shieldmori.git
cd shieldmori
```

### 2. Get a VirusTotal API Key

1. Create a free account at [virustotal.com](https://www.virustotal.com)
2. Go to your profile → **API Key**
3. Copy your key

### 3. Set up the backend

The frontend calls two API endpoints that you need to implement on your backend:

| Endpoint | Method | Description |
|---|---|---|
| `/api/scan` | `GET` | Scan a URL, domain, IP, or hash |
| `/api/scan-file` | `POST` | Upload a file for analysis |

#### `/api/scan` — Query Parameters

| Param | Values | Description |
|---|---|---|
| `type` | `url` · `domain` · `ip` · `hash` | Type of target to scan |
| `value` | string | The actual target (URL, domain, IP, or hash) |

#### Expected Response Format

```json
{
  "success": true,
  "result": {
    "name": "example.com",
    "sha256": "abc123...",
    "md5": "def456...",
    "size": 204800,
    "lastAnalysis": 1700000000000,
    "reputation": -5,
    "stats": {
      "malicious": 3,
      "suspicious": 1,
      "undetected": 68,
      "harmless": 2,
      "timeout": 0
    },
    "engines": [
      {
        "engine": "Kaspersky",
        "category": "malicious",
        "result": "Trojan.GenericKD"
      },
      {
        "engine": "Bitdefender",
        "category": "undetected",
        "result": null
      }
    ]
  }
}
```

> `category` can be: `malicious` · `suspicious` · `undetected` · `harmless` · `timeout`

#### `/api/scan-file` — Multipart Form

Send a `multipart/form-data` POST with a `file` field. The backend should upload it to VirusTotal and return the analysis ID. The frontend will then poll `/api/scan?type=hash&value=<sha256>` until results are ready.

---

## Project Structure

```
shieldmori/
├── index.html        # Single-file frontend (all CSS + JS inline)
├── README.md
└── server/           # Example backend (optional, not included)
    └── ...
```

> The entire frontend lives in a single `index.html` — no build step, no dependencies, no npm required.

---

## Scan Flow

```
User Input
    │
    ├── URL / Domain / IP / Hash ──► GET /api/scan?type=...&value=...
    │                                        │
    │                                        └──► VirusTotal API v3
    │                                                    │
    │                                             Results returned
    │
    └── File Upload ──► Compute SHA-256 locally (Web Crypto API)
                            │
                            ├── Hash exists? ──► GET /api/scan?type=hash&value=<sha256>
                            │
                            └── Not found? ──► POST /api/scan-file
                                                    │
                                              Poll every 5s until done
```

---

## Verdict Logic

| Flagged Engines | Verdict     |
|-----------------|-------------|
| 0               | ✅ Clean     |
| 1 – 4           | ⚠️ Suspicious |
| 5+              | ❌ Malicious  |

---

## Screenshots

> _Add your own screenshots here_

| Home | Scan Panel | Results |
|------|------------|---------|
| ![Home]() | ![Scan]() | ![Results]() |

---

## Customization

The entire design is token-based via CSS custom properties at the top of `index.html`:

```css
:root {
  --paper:  #EDEAE3;   /* Background */
  --ink:    #141414;   /* Text */
  --red:    #C9292B;   /* Accent / threat color */
  --amber:  #C97006;   /* Suspicious color */
  --green:  #1a7a4a;   /* Clean color */
}
```

---

## Privacy

- **No data is stored.** All scan targets are forwarded directly to VirusTotal.
- **File hashing is done client-side** using the browser's native Web Crypto API — the actual file content is never logged.
- VirusTotal may retain submitted files and URLs per their [Privacy Policy](https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy).

---

## Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'feat: add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## License

MIT © [YukiiKazunomiya](https://github.com/YukiiKazunomiya)

---

<div align="center">
  <sub>Built Powered by <a href="https://www.virustotal.com">VirusTotal</a></sub>
</div>
