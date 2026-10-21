# APKScope

AI-assisted Android APK security and forensic analysis platform (SOC / blue-team focused).

## Goal
Take a suspicious APK, analyse it, extract IoCs, score the risk with a clear explanation,
and help an analyst triage it quickly.

## Planned features
- [ ] Static analysis: manifest, permissions, exported components
- [ ] IoC extraction: URLs, IPs, domains
- [ ] Signing certificate and third-party library analysis
- [ ] Evasion detection: obfuscation, dynamic loading, encrypted assets
- [ ] Explainable risk score
- [ ] MITRE ATT&CK for Mobile mapping
- [ ] Threat intel enrichment (VirusTotal, MalwareBazaar)
- [ ] Dashboard with multi-APK comparison
- [ ] YARA rule generation
- [ ] PDF forensic report

## Setup
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python analyze.py path/to/app.apk
```

## Safety
Never run or install real malware on your main machine. Keep samples in `samples/` (git-ignored).
