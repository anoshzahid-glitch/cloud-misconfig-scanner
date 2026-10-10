"""AI-generated remediation text (Gemini free tier).

The AI only EXPLAINS how to fix a finding. Severity and detection are decided by the
rule engine, never by the model. If the API key is missing or a call fails, the
dashboard still works and shows a plain fallback message.
"""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_FILE = ROOT / "remediation_cache.json"
DEFAULT_MODEL = "gemini-3.8-flash"   # override with GEMINI_MODEL in .env if Google renames it


def _load_env():
    """Tiny .env reader so we don't need an extra dependency."""
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def build_prompt(finding):
    return (
        "You are a cloud security assistant helping a small company in Germany fix an "
        "AWS misconfiguration. Be concise and practical.\n\n"
        f"Finding: {finding['title']}\n"
        f"Severity (already decided, do not change it): {finding['severity']}\n"
        f"Why it matters: {finding['description']}\n\n"
        "Reply in plain text with exactly these parts:\n"
        "1. Risk: one or two sentences in simple language.\n"
        "2. Fix: three to five numbered steps (AWS Console or AWS CLI).\n"
        "3. Check: one sentence on how to confirm the fix worked.\n"
        "Do not invent resource names. Do not use markdown headings."
    )


def _read_cache():
    try:
        return json.loads(CACHE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def get_remediation(finding):
    """Return (text, source) where source is 'ai', 'cache' or 'fallback'."""
    rule_id = finding["rule_id"]
    cache = _read_cache()
    if rule_id in cache:
        return cache[rule_id], "cache"

    _load_env()
    key = os.environ.get("GEMINI_API_KEY")
    fallback = (f"{finding['description']} (AI remediation unavailable - "
                "check GEMINI_API_KEY in .env and your internet connection.)")
    if not key:
        return fallback, "fallback"
    try:
        from google import genai
        client = genai.Client(api_key=key)
        model = os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
        resp = client.models.generate_content(model=model, contents=build_prompt(finding))
        text = (resp.text or "").strip()
        if not text:
            return fallback, "fallback"
        cache[rule_id] = text
        CACHE_FILE.write_text(json.dumps(cache, indent=2))
        return text, "ai"
    except Exception as e:  # network, quota, bad key, SDK missing...
        return f"{fallback} [{type(e).__name__}]", "fallback"


if __name__ == "__main__":
    from scanner.engine import scan_file
    first = scan_file("sample_configs/vulnerable_1.json")[0]
    text, source = get_remediation(first)
    print(f"[{source}] {first['rule_id']}\n{text}")
