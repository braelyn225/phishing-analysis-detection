# PhishGuard

PhishGuard is a phishing email triage tool that parses `.eml` files, extracts IOCs (URLs/domains/IPs/hashes),
applies heuristic detections, computes a weighted risk score, and generates incident-ready reports.

## Features
- Parse email headers (From, Reply-To, Subject, Authentication-Results)
- Extract IOCs: URLs (incl. `hxxp` / `[.]` deobfuscation), domains, IPs, hashes
- Heuristic scoring (Reply-To mismatch, punycode, suspicious TLDs, urgency keywords, SPF/DKIM/DMARC failures if present)
- Outputs: `report.json` + `report.md`

## Install
```bash
pip install -e .
```

## Run
```bash
phishguard path/to/email.eml -o out
```

Output
- `out/report.json`
- `out/report.md`

## Why this project
This mirrors real SOC phishing triage: extracting indicators, identifying suspicious patterns, and producing reusable artifacts.

## Repository Layout
```
phishguard/
  phishguard/
    __init__.py
    cli.py
    parser_eml.py
    indicators.py
    scoring.py
    report.py
    utils.py
  samples/
    README.md
  tests/
    test_indicators.py
    test_scoring.py
  .github/workflows/ci.yml
  .gitignore
  LICENSE
  README.md
  requirements.txt
  pyproject.toml
```

## Optional upgrades
- Dockerfile + docker run usage
- YAML config for weights/TLD lists
- Attachment hash extraction (walk MIME parts and hash attachment bytes)
- Export to STIX 2.1 (basic indicators)
- VirusTotal/URLHaus integration behind an API key flag (avoid hard dependency)
