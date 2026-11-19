# AutoReconX

### Automated Vulnerability Assessment & Reporting Framework

**AutoReconX** is a modular Python-based security automation framework designed to orchestrate open-source security tools, consolidate vulnerability findings, prioritize risks, and generate structured assessment reports.

The project aims to simplify repetitive vulnerability assessment workflows through a unified command-line interface and extensible scanner architecture.

> **Project status:** Early development — target validation, scope verification, and CLI foundation implemented. Scanner integrations are under development.

---

## Project Objectives

- Automate repetitive vulnerability assessment workflows.
- Integrate open-source security scanning tools.
- Normalize findings from multiple scanner outputs.
- Classify vulnerabilities by severity.
- Generate consolidated security assessment reports.
- Provide actionable remediation recommendations.

## Planned Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python 3.13 |
| CLI framework | Typer |
| Terminal interface | Rich |
| Network scanning | Nmap |
| Web application scanning | OWASP ZAP |
| Template-based detection | Nuclei |
| Data validation | Pydantic |
| Configuration | YAML |
| Report generation | Jinja2 |
| PDF generation | WeasyPrint |
| Testing | Pytest |

## Architecture

```text
                 AutoReconX CLI
                       |
                       v
              Target Validation
                       |
                       v
               Scope Enforcement
                       |
                       v
              Scan Orchestrator
                       |
          +------------+------------+
          |            |            |
          v            v            v
        Nmap          ZAP         Nuclei
          |            |            |
          +------------+------------+
                       |
                       v
              Result Normalization
                       |
                       v
               Severity Engine
                       |
                       v
               Remediation Engine
                       |
                       v
               Report Generator
                       |
                 HTML / PDF
```

*The scanner, normalization, remediation and reporting components are planned architecture, not yet implemented.*

## Current Features

- Modular Python project structure.
- Command-line interface using Typer.
- Rich terminal output.
- IP address validation.
- Domain name validation.
- HTTP/HTTPS URL validation.
- YAML-based approved target configuration.
- Exact hostname scope verification.
- Unit tests using Pytest.

## Project Structure

```text
AutoReconX/
│
├── autoreconx/
│   ├── __init__.py
│   ├── main.py
│   ├── cli.py
│   │
│   └── core/
│       ├── __init__.py
│       ├── validator.py
│       └── scope.py
│
├── tests/
│   └── test_validator.py
│
├── scans/
├── reports/
│
├── config.example.yaml
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

### Prerequisites

- Windows, Linux or macOS
- Python 3.13+
- Git

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/AutoReconX.git
cd AutoReconX
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
py -3.13 -m venv venv
.\venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure approved scope

```powershell
Copy-Item config.example.yaml config.yaml
```

Edit `config.yaml` to specify targets you are authorized to assess.

## Usage

### Display framework version

```bash
python -m autoreconx.main version
```

### Display framework information

```bash
python -m autoreconx.main info
```

### Validate a target

```bash
python -m autoreconx.main validate 127.0.0.1
```

### Verify target scope

```bash
python -m autoreconx.main scope-check 127.0.0.1
```

### Run tests

```bash
python -m pytest -v
```

## Development Roadmap

| Milestone | Description | Status |
|---|---|---|
| M01 | Project initialization and CLI | Completed |
| M02 | Target validation and scope controls | Completed |
| M03 | Nmap integration | Planned |
| M04 | OWASP ZAP integration | Planned |
| M05 | Nuclei integration | Planned |
| M06 | Unified vulnerability engine | Planned |
| M07 | Remediation recommendation engine | Planned |
| M08 | HTML/PDF reporting | Planned |
| M09 | Testing and quality assurance | Planned |
| M10 | Documentation and release | Planned |

## Security Considerations

AutoReconX is intended for authorized security assessments and controlled laboratory environments.

- Only assess systems you own or have explicit permission to test.
- Configure approved targets before scanning.
- Respect defined assessment scope and scan restrictions.
- Avoid destructive or intrusive testing by default.
- Protect credentials and sensitive assessment data.
- Treat automated findings as potential vulnerabilities until manually validated.

## Disclaimer

This project is developed for educational purposes, authorized penetration testing, and security assessment automation.

The author is not responsible for unauthorized use or damage caused by misuse of this software.

## License

MIT License.
