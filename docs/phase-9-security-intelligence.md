# Phase 9: Advanced Security Intelligence

## Overview
Phase 9 upgrades the Email Analysis Agent into an enterprise-grade **AI Email Security Platform** by adding automated static analysis, language processing, pattern matching, brand spoofing detectors, and relational campaign correlations.

## Architecture & Submodules
The advanced intelligence services are organized inside `src/security_intelligence/`:

```
src/security_intelligence/
├── behavior/           # Linguistic behavioral analyzer (social engineering, BEC, urgency)
├── brand/              # Brand impersonation detection (display-name, typosquatting, homographs)
├── campaign/           # Database-backed coordinated campaign correlation
├── ioc/                # Regex-based IOC extractor (IPs, domains, hashes, registry, mutexes)
├── malware/            # Static file scanner (Office macros, double extensions, magic bytes, entropy)
├── models/             # EnterpriseSecurityReport Pydantic models
├── ocr/                # Simulated image and scanned document text extractor
├── qr/                 # QR Code decoder and redirect expander
├── risk/               # MITRE ATT&CK mapping and mitigation recommendations
├── threat_intel/       # Pluggable Threat Intelligence reputation feeds
└── __init__.py         # Package exports
```

## Core Intelligence Services

### 1. OCR Intelligence (`ocr/ocr_service.py`)
Extracts, normalizes, and sanitizes text from image attachments (PNG, JPG) or scanned PDF formats, passing the derived strings back to the email body investigation pipeline.

### 2. QR Code Intelligence (`qr/qr_service.py`)
Detects embedded QR codes, decodes underlying URL indicators, expands shortened redirection links (e.g. `bit.ly`, `tinyurl`), and feeds targets to the URL threat scanner.

### 3. Brand Impersonation (`brand/brand_service.py`)
- **Display name spoofing**: Alerts if the display name contains targeted high-value brands (e.g. PayPal, Apple, Amazon) but is sent from a public domain (e.g. Gmail).
- **Typosquatting**: Leverages Levenshtein distance ($distance \le 2$) to detect look-alike domains (e.g. `micr0soft.com`).
- **Homographs**: Decodes Punycode IDNA domains (`xn--...`) and computes Levenshtein distance on decoded unicode strings to block homoglyph character substitutions.

### 4. IOC Extractor (`ioc/ioc_extractor.py`)
High-speed regex scanner extracting IPs, email addresses, domains, URLs, MD5/SHA-1/SHA-256 hashes, registry keys, process names, and mutexes. Dedupes domains nested inside URL patterns.

### 5. Threat Intelligence (`threat_intel/threat_intel_service.py`)
Pluggable provider interface (`IThreatIntelProvider`) checking IPs, domains, and file hashes against local or cloud-based reputation feeds to generate threat scores.

### 6. Malware static scanner (`malware/malware_service.py`)
Examines attachments for:
- Magic bytes signatures (`MZ` for PE executables, `%PDF` for PDFs, `PK` for ZIP archives).
- Shannon Entropy: Mathematical byte dispersion check ($entropy > 7.2$) flagging packed or encrypted executable payloads.
- VBA Macros: Recursively decompresses zip files to scan for macro scripts and shell triggers.
- Disguised extensions (`statement.pdf.exe`).

### 7. Campaign Correlation (`campaign/campaign_correlation.py`)
SQLite database correlation engine identifying coordinated campaigns across multiple historic runs based on matching senders, subject templates, or URL infrastructure.

### 8. Behavioral Analysis (`behavior/behavior_analyzer.py`)
Scans text content for linguistic indicators mapping to BEC (Wire transfers, CEO requests), Credential Harvesting (password resets, verify account), and Financial Fraud.

### 9. Risk Enrichment (`risk/risk_enrichment.py`)
Enriches security profiles with MITRE ATT&CK technique IDs (e.g., T1566 "Phishing", T1204.002 "User Execution: Malicious File") and details, threat categories, and mitigation recommendations.

## Security Report Schema (`models/security_report.py`)
Compiles structured enterprise-grade report models including all threat categorizations, MITRE maps, extracted IOCs, and recommended action steps.

## Testing & Verification
Tests are placed in `tests/test_phase9_intelligence.py`. Run tests using:
```bash
.venv\Scripts\pytest.exe tests/test_phase9_intelligence.py
```
