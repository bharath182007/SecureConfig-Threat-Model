# SecureConfig: Threat Modeling & Secure Configuration Audit

A beginner-friendly defensive cybersecurity portfolio project. It combines a lightweight threat model with a Python script that checks a few local security indicators and exports a JSON report.

## Features
- Documents assets, trust boundaries, threats, risks, and mitigations.
- Checks whether the host firewall appears enabled (Windows, Linux with UFW, or macOS).
- Checks a short list of common services listening on **localhost only**.
- Records operating-system and Python details.
- Exports a timestamped JSON report without changing system settings.

## Requirements
- Python 3.9+
- No third-party packages

## Run
```bash
python audit.py
```
To choose an output path:
```bash
python audit.py --output reports/my-audit.json
```

Some checks depend on the operating system and installed utilities. If a check cannot be performed, the report records `unknown` rather than assuming the system is insecure. This tool is a learning aid, not a full vulnerability scanner or compliance assessment.

## Project structure
```text
secureconfig-threat-model/
├── audit.py
├── README.md
├── docs/
│   ├── threat-model.md
│   └── secure-configuration-checklist.md
└── reports/
    └── sample-report.json
```

## Safety and privacy
- Checks only the computer on which it runs.
- Local port checks connect to loopback (`127.0.0.1`) only.
- Does not exploit vulnerabilities, change settings, or transmit data.
- Review the report before sharing it; it contains host and platform details.

## Suggested GitHub description
`A Python-based defensive security audit with a STRIDE-inspired threat model and secure configuration checklist.`

## Next improvements
- Add unit tests for platform parsing.
- Add a simple HTML report.
- Add checks for automatic updates and disk encryption, with clear OS-specific support.
