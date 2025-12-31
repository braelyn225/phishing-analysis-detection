# Phishing Analysis & Detection

## Project Description
This project delivers a lightweight phishing analysis & detection toolkit that evaluates URLs and raw email content, plus a basic TCP port scanner for quick network reconnaissance. It provides structured findings, a risk score, and a verdict that can be extended with additional signals (threat intelligence, ML models, reputation feeds, etc.).

## Objectives
- Provide an initial, working phishing analysis pipeline in Python.
- Offer basic URL and email heuristics for quick risk screening.
- Explain the system architecture, folder layout, and chosen methods.
- Deliver a command-line interface that emits human-readable or JSON output.
- Include a simple port scanner that reports open and closed ports.

## System Architecture
1. **Input Layer**: Receives a URL, raw email file, or scan target.
2. **Parsing Layer**: Normalizes URLs, parses email headers/body, and extracts embedded URLs.
3. **Detection Layer**: Applies heuristic checks (TLD risk, IP-based URLs, keywords, urgency, etc.).
4. **Scoring Layer**: Aggregates findings into a risk score and verdict.
5. **Scanning Layer**: Attempts TCP connections to user-specified ports.
6. **Output Layer**: Prints findings in text or JSON format.

## Folder Structure
```
phishing-analysis-detection/
├── README.md
└── src/
    └── phishing_detector/
        ├── __init__.py
        ├── analyzer.py
        ├── main.py
        └── port_scanner.py
```

## Initial Implementation (Python)
The core logic lives in `src/phishing_detector/analyzer.py`, with a CLI entry point in `src/phishing_detector/main.py`.

### Example Usage
```bash
python -m phishing_detector.main --url "http://login.verify-account.example.xyz"
python -m phishing_detector.main --email-file sample.eml --output json
python -m phishing_detector.main --scan-host scanme.nmap.org --ports "22,80,443,8000-8100"
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

**Port Scanning** includes:
- TCP connection checks for user-specified ports and ranges.
- Simple open/closed reporting with configurable timeouts.

## Methods & Technologies
- **Python standard library** (`urllib.parse`, `email`, `re`, `dataclasses`) to parse content and run rule-based checks.
- **Heuristic scoring** to keep the initial implementation transparent and explainable.
- **JSON/text output** to integrate with downstream systems or dashboards.

## Next Steps (Ideas)
- Add DNS and WHOIS enrichment.
- Integrate ML models for classification.
- Connect to threat intelligence feeds.
- Expand email parsing for HTML content and attachments.
