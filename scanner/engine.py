"""Run every rule against a configuration and return ranked findings."""
import sys

from scanner.parser import load_config
from scanner.rules import RULES

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def scan(config):
    """Return a list of findings (one per affected resource), most severe first."""
    findings = []
    for rule in RULES:
        for resource in rule.check(config):
            findings.append({
                "rule_id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "category": rule.category,
                "resource": resource,
                "description": rule.description,
                "cis": rule.cis,
                "nist": rule.nist,
                "waf": rule.waf,
            })
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["rule_id"], f["resource"]))
    return findings


def scan_file(path):
    return scan(load_config(path))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python -m scanner.engine <config.json|config.yaml>")
    results = scan_file(sys.argv[1])
    print(f"{len(results)} finding(s)")
    for f in results:
        print(f"[{f['severity']:<8}] {f['rule_id']}  {f['resource']}  -  {f['title']}")
