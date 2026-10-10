# Cloud Misconfiguration Scanner

AI-assisted AWS misconfiguration scanner and risk prioritisation dashboard for SMEs.
MSc Cybersecurity, COM7014 Advanced Computing Project (Arden University Berlin).

- Reads an exported AWS configuration (JSON or YAML). No live cloud access.
- 12 curated rules with fixed severity, mapped to CIS AWS Foundations / NIST CSF 2.0 / AWS Well-Architected.
- Findings ranked by severity in a Streamlit dashboard.
- Gemini (free tier) only explains how to fix a finding; it never decides detection or severity.

## Run
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
echo "GEMINI_API_KEY=your_key" > .env     # optional, for AI remediation
streamlit run app.py
```

## Evaluate
```
python evaluate.py
```
Compares scanner output with `sample_configs/ground_truth.json` (precision, recall, scan time).

## Layout
`scanner/rules.py` rules, `scanner/parser.py` loader, `scanner/engine.py` scan logic,
`scanner/remediation.py` AI text, `app.py` dashboard, `sample_configs/` test data.
