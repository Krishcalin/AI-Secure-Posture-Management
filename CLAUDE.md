# CLAUDE.md — AI Security Posture Management (AI-SPM) Scanner

## Project Overview

This is an **AI Security Posture Management (AI-SPM)** static-analysis scanner that identifies security misconfigurations, vulnerabilities, and compliance gaps across the entire AI/ML lifecycle — from data ingestion through model training, deployment, and inference.

- **Language**: Python 3.10+ (no external dependencies — pure stdlib)
- **Scanner file**: `ai_spm_scanner.py` (single self-contained file)
- **Version**: 1.0.0
- **License**: MIT

## Architecture

The scanner follows a consistent architecture pattern shared across all scanners in this portfolio:

1. **Module-level rule dicts** — categorised lists of `{id, category, name, severity, pattern, description, cwe, recommendation, compliance}`.
2. **`Finding` dataclass** — `rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve, compliance`.
3. **`AISPMScanner` class** — with `SKIP_DIRS`, `SEVERITY_ORDER`, `SEVERITY_COLOR`, ANSI constants, and AI inventory tracking.
4. **Methods**: `scan_path` → `_scan_directory` → `_dispatch_file` → language-specific scanners → `_sast_scan` regex engine.
5. **CLI**: `argparse` with `target`, `--json`, `--html`, `--severity`, `--verbose`, `--version`.
6. **Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise.

## Rule Categories

| Category | Prefix | Count |
|----------|--------|-------|
| Model Security | AISPM-MODEL-* | 10 |
| Prompt / LLM Security | AISPM-PROMPT-* | 10 |
| Data Pipeline | AISPM-DATA-* | 6 |
| Privacy | AISPM-PRIV-* | 6 |
| Guardrails | AISPM-GUARD-* | 8 |
| Agent Security | AISPM-AGENT-* | 5 |
| RAG Security | AISPM-RAG-* | 5 |
| Secrets (Python) | AISPM-SECRET-* | 8 |
| Shadow AI | AISPM-SHADOW-* | 4 |
| Infrastructure | AISPM-INFRA-* | 8 |
| .env Rules | AISPM-ENV-* | 6 |
| JS/TS Rules | AISPM-JS-* | 8 |
| Config (YAML) | AISPM-CFG-* | 8 |
| Docker | AISPM-DOCKER-* | 4 |
| Supply Chain (PyPI) | AISPM-DEP-CVE-* | 20 packages |
| Supply Chain (npm) | AISPM-DEP-CVE-* | 3 packages |

## Compliance Frameworks

Every finding maps to one or more compliance frameworks:

- **NIST AI RMF** — GOVERN, MAP, MEASURE, MANAGE
- **EU AI Act** — High Risk, Limited Risk, GPAI
- **OWASP ML Top 10** — ML01 through ML10
- **MITRE ATLAS** — Reconnaissance, Resource Development, Initial Access, ML Attack Execution, Persistence, Exfiltration, Impact

## File Types Scanned

`.py`, `.pyw`, `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.env`, `.yaml`, `.yml`, `.toml`, `Dockerfile`, `requirements*.txt`, `Pipfile`, `pyproject.toml`, `package.json`, `.ipynb`

## Development Guidelines

### Adding New Rules

1. Add the rule dict to the appropriate `*_RULES` list at module level.
2. Follow the ID pattern: `AISPM-{CATEGORY}-{NNN}` (zero-padded 3-digit).
3. Every rule must include: `id`, `category`, `severity`, `name`, `pattern` (regex), `description`, `cwe`, `recommendation`, `compliance` (list of framework codes).
4. Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
5. Compliance codes must reference keys in `COMPLIANCE_MAP`.

### Adding New CVEs

Add entries to `AI_VULNERABLE_PACKAGES` (Python) or `AI_NPM_VULNERABLE_PACKAGES` (npm) with: `package`, `cve`, `severity`, `fixed` (first safe version), `desc`.

### Adding New File Types

1. Add extension to the appropriate class-level set.
2. Add a `_scan_{type}` method.
3. Register dispatch in `_dispatch_file`.

### Testing

Run against the intentionally vulnerable test samples:

```bash
python ai_spm_scanner.py tests/samples/ --verbose
python ai_spm_scanner.py tests/samples/ --json report.json --html report.html
python ai_spm_scanner.py tests/samples/requirements_ai.txt --severity HIGH
```

### Test Sample Files

- `tests/samples/vulnerable_ai_app.py` — insecure Python AI patterns
- `tests/samples/vulnerable_frontend.tsx` — insecure JS/TS AI frontend
- `tests/samples/.env.test` — exposed AI API keys
- `tests/samples/requirements_ai.txt` — packages with known CVEs
- `tests/samples/Dockerfile.ai` — insecure AI container
- `tests/samples/ml_pipeline.yaml` — insecure ML pipeline config

## Conventions

- Single-file scanner — all rules, engine, and reports in `ai_spm_scanner.py`.
- No external dependencies — only Python stdlib.
- HTML reports use dark theme with purple gradient (`#6c5ce7` → `#a855f7` → `#ec4899`).
- Keep rule descriptions actionable — always include a concrete `recommendation`.
- Use British English in descriptions (sanitise, unauthorised, etc.) for consistency with existing rules.
