# Phishing Analysis & Detection

## Project Description
This project delivers a lightweight phishing analysis & detection toolkit that evaluates URLs and raw email content. It provides structured findings, a risk score, and a verdict that can be extended with additional signals (threat intelligence, ML models, reputation feeds, etc.).

## Objectives
- Provide an initial, working phishing analysis pipeline in Python.
- Offer basic URL and email heuristics for quick risk screening.
- Explain the system architecture, folder layout, and chosen methods.
- Deliver a command-line interface that emits human-readable or JSON output.

## System Architecture
1. **Input Layer**: Receives a URL or raw email file.
2. **Parsing Layer**: Normalizes URLs, parses email headers/body, and extracts embedded URLs.
3. **Detection Layer**: Applies heuristic checks (TLD risk, IP-based URLs, keywords, urgency, etc.).
4. **Scoring Layer**: Aggregates findings into a risk score and verdict.
5. **Output Layer**: Prints findings in text or JSON format.

## Folder Structure
```
phishing-analysis-detection/
├── README.md
├── LICENSE
├── pyproject.toml
├── samples/
│   ├── benign.eml
│   ├── benign_url.txt
│   ├── suspicious.eml
│   └── suspicious_url.txt
├── src/
│   └── phishing_detector/
│       ├── __init__.py
│       ├── analyzer.py
│       └── main.py
└── tests/
    └── test_analyzer.py
```

## Install (one-liner)
```bash
pip install -e .
```

> **Module path note:** The CLI is invoked as `python -m phishing_detector.main`. Because the
> package lives under `src/`, you must either install the project (recommended) or set
> `PYTHONPATH=src` when running from source to avoid `ModuleNotFoundError`.

## Quickstart (copy/paste)
```bash
pip install -e .
phishing-detector --url "$(cat samples/suspicious_url.txt)" --output json
phishing-detector --email-file samples/suspicious.eml --output json
```

## Example Usage
```bash
phishing-detector --url "http://login.verify-account.example.xyz"
phishing-detector --email-file samples/suspicious.eml --output json
```

## Safety: Defang URLs Before Sharing
When sharing results in tickets or chat, defang URLs to prevent accidental clicks. Example:
- `http://login.verify-account.example.xyz` → `hxxp://login[.]verify-account[.]example[.]xyz`

## Expected JSON Output (snippet)
> **Defanged for safety**
```json
[
  {
    "target": "hxxp://login[.]verify-account[.]example[.]xyz",
    "score": 9,
    "verdict": "high risk",
    "findings": [
      {"label": "tld", "detail": "Suspicious TLD '.xyz'", "severity": "high"},
      {"label": "keywords", "detail": "Sensitive keywords found: account, login, verify", "severity": "medium"}
    ]
  }
]
```

## Basic Phishing Detection Logic
**URL Analysis** includes checks for:
- IP address-based hostnames.
- Unusual schemes or plain HTTP usage.
- Long URLs, excessive subdomains, or hyphenated domains.
- Suspicious TLDs (e.g., `.xyz`, `.zip`).
- Phishing-related keywords in the host/path/query.

**Email Analysis** includes checks for:
- Mismatched `Reply-To` vs `From` headers.
- Sensitive keywords in the subject line.
- Embedded URLs and follow-on URL analysis.
- Urgent language in the message body.

## Scoring Transparency
Scores are additive points from heuristic checks (higher = riskier). Thresholds map to verdicts.

### URL signals
| Signal | Points |
| --- | --- |
| Unusual scheme (not http/https) | +2 |
| IP address hostname | +3 |
| `@` in URL | +3 |
| Length > 75 chars | +2 |
| 3+ subdomains | +2 |
| Hyphenated hostname | +1 |
| Suspicious TLD | +3 |
| Sensitive keyword hits | +2 |
| HTTP (unencrypted) | +1 |

### Email signals
| Signal | Points |
| --- | --- |
| Reply-To differs from From | +3 |
| Sensitive keywords in subject | +2 |
| URL(s) present | +1 |
| Worst risky URL score | +0 to +4 (single worst URL) |
| Urgent language | +2 |

### Verdict thresholds
| Score | Verdict |
| --- | --- |
| 0–2 | low risk |
| 3–5 | suspicious |
| 6+ | high risk |

## Methods & Technologies
- **Python standard library** (`urllib.parse`, `email`, `re`, `dataclasses`) to parse content and run rule-based checks.
- **Heuristic scoring** to keep the initial implementation transparent and explainable.
- **JSON/text output** to integrate with downstream systems or dashboards.

## Samples
Use the `samples/` folder for repeatable demos:
- `samples/benign_url.txt`
- `samples/suspicious_url.txt`
- `samples/benign.eml`
- `samples/suspicious.eml`

## Quality Signals
- ✅ MIT license
- ✅ Pytest coverage for core scoring paths
- ✅ CI workflow running ruff + pytest

## Next Steps (Ideas)
- Add DNS + WHOIS enrichment for domain age and newly registered domains.
- Integrate URL reputation checks (Safe Browsing or open threat intel sources).
- Expand email header analysis for SPF/DKIM/DMARC verdicts and Received-chain basics.
- Integrate ML models for classification.
- Connect to additional threat intelligence feeds.
- Expand email parsing for HTML content and attachments.
