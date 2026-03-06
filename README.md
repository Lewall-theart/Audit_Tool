# Windows Audit Project

Automated Windows log-based security audit pipeline.

## Overview

This project reads collected Windows host logs, extracts security attributes, maps them to a baseline, evaluates compliance, and generates reports in JSON, HTML, and CSV.

The default execution flow:

1. Load raw host logs from `logs/windows/*.txt`
2. Parse and normalize log lines
3. Extract security attributes and evidence
4. Map extracted attributes to `knowledge_base/windows_security_baseline.json`
5. Evaluate each control as `PASS`, `FAIL`, or `UNKNOWN`
6. Aggregate host-level and overall compliance score
7. Export reports to `output/`

## Project Structure

- `main.py`: orchestration entry point
- `inputs/log_file_loader.py`: loads text logs per host
- `analyzers/`: parsing, attribute extraction, and evidence building
- `engine/`: mapping, rule evaluation, compliance scoring
- `knowledge_base/windows_security_baseline.json`: expected control values
- `report/`: report generators (`json`, `html`, `csv`)
- `collectors/` and `inputs/live_collector.py`: collector stubs for future live collection

## Key Technical Notes

- Baseline currently contains 40 controls.
- Rule operators supported in evaluation:
  - `eq`
  - `gte`
  - `lte`
  - `between`
- If either expected value or observed value is missing, status is `UNKNOWN`.
- Overall score is calculated from evaluated controls only (`PASS + FAIL`), excluding `UNKNOWN`.
- Report generation has write-fallback logic: if `output/report.*` is locked, timestamped files are created automatically.

## Requirements

- Python 3.10+ (stdlib only, no external package required)

## Run

```powershell
cd "d:\New folder\all\windows_audit_project"
python main.py
```

Expected output artifacts:

- `output/report.json`
- `output/report.html`
- `output/report.csv`
