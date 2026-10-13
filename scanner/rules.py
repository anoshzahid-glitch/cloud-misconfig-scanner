"""Rule definitions for the AWS misconfiguration scanner.

Each rule has a fixed severity, set at definition time (never computed by the AI),
and a check function that returns a list of affected resources.
"""
from dataclasses import dataclass
from typing import Callable

ADMIN_PORTS = (22, 3389)
WORLD = ("0.0.0.0/0", "::/0")
KEY_MAX_AGE_DAYS = 90


@dataclass
class Rule:
    id: str
    title: str
    severity: str          # Critical / High / Medium / Low
    category: str          # IAM / Network / Storage / Logging / Database
    description: str
    cis: str               # CIS AWS Foundations Benchmark v5.0.0 (31 March 2025) recommendation number
    nist: str              # NIST CSF 2.0 subcategory
    waf: str               # AWS Well-Architected Security Pillar area
    check: Callable[[dict], list]


def _w(x):
    """Wildcard test that also handles lists like ["*"]."""
    return x == "*" or (isinstance(x, list) and "*" in x)


# ---- check functions: each returns a list of affected resource names ----

def chk_root(cfg):
    a = cfg.get("account", {})
    if not a.get("root_mfa_enabled", False) or a.get("root_access_keys", 0) > 0:
        return ["root account"]
    return []

def chk_sg_open(cfg):
    hits = []
    for sg in cfg.get("security_groups", []):
        for r in sg.get("ingress", []):
            lo, hi = r.get("from_port", 0), r.get("to_port", 65535)
            if r.get("cidr") in WORLD and any(lo <= p <= hi for p in ADMIN_PORTS):
                hits.append(sg.get("id", "unknown-sg"))
                break
    return hits

def chk_s3_public(cfg):
    return [b["name"] for b in cfg.get("s3_buckets", []) if not b.get("public_access_block", False)]

def chk_rds_public(cfg):
    return [d["id"] for d in cfg.get("rds_instances", []) if d.get("publicly_accessible", False)]

def chk_user_mfa(cfg):
    return [u["name"] for u in cfg.get("iam_users", [])
            if u.get("console_access", False) and not u.get("mfa_enabled", False)]

def chk_wildcard_policy(cfg):
    hits = []
    for p in cfg.get("iam_policies", []):
        for s in p.get("statements", []):
            if s.get("effect") == "Allow" and _w(s.get("action")) and _w(s.get("resource")):
                hits.append(p.get("name", "unknown-policy"))
                break
    return hits

def chk_cloudtrail(cfg):
    ct = cfg.get("cloudtrail", {})
    if not ct.get("enabled", False) or not ct.get("multi_region", False):
        return ["cloudtrail"]
    return []

def chk_s3_encrypt(cfg):
    return [b["name"] for b in cfg.get("s3_buckets", []) if not b.get("encryption", False)]

def chk_key_age(cfg):
    return [u["name"] for u in cfg.get("iam_users", [])
            if u.get("access_key_age_days", 0) > KEY_MAX_AGE_DAYS]

def chk_ebs(cfg):
    return [v["id"] for v in cfg.get("ebs_volumes", []) if not v.get("encrypted", False)]

def chk_rds_encrypt(cfg):
    return [d["id"] for d in cfg.get("rds_instances", []) if not d.get("encrypted", False)]

def chk_s3_version(cfg):
    return [b["name"] for b in cfg.get("s3_buckets", []) if not b.get("versioning", False)]


RULES = [
    Rule("IAM-001", "Root account lacks MFA or has access keys", "Critical", "IAM",
         "The root user has unrestricted access; it needs MFA and no access keys.",
         "1.3 / 1.4", "PR.AA-03", "Identity and access management", chk_root),
    Rule("EC2-001", "Security group exposes SSH/RDP to the internet", "Critical", "Network",
         "Admin ports open to 0.0.0.0/0 allow brute-force and exploit attempts from anywhere.",
         "5.3", "PR.IR-01", "Infrastructure protection", chk_sg_open),
    Rule("S3-001", "S3 bucket does not block public access", "Critical", "Storage",
         "Without Block Public Access, a bucket policy or ACL mistake can expose data.",
         "2.1.4", "PR.DS-01", "Data protection", chk_s3_public),
    Rule("RDS-001", "RDS instance is publicly accessible", "Critical", "Database",
         "A database reachable from the internet is exposed to direct attack.",
         "2.2.3", "PR.IR-01", "Infrastructure protection", chk_rds_public),
    Rule("IAM-002", "Console user without MFA", "High", "IAM",
         "A stolen password alone gives full console access.",
         "1.9", "PR.AA-03", "Identity and access management", chk_user_mfa),
    Rule("IAM-003", "Policy grants full admin (* on *)", "High", "IAM",
         "Violates least privilege; one compromised identity can control the account.",
         "1.15", "PR.AA-05", "Identity and access management", chk_wildcard_policy),
    Rule("LOG-001", "CloudTrail disabled or not multi-region", "High", "Logging",
         "Without audit logs, attacks and misuse cannot be detected or investigated.",
         "3.1", "PR.PS-04", "Detection", chk_cloudtrail),
    Rule("S3-002", "S3 bucket not encrypted at rest", "High", "Storage",
         "Unencrypted objects raise the impact of any storage-level compromise.",
         "n/a", "PR.DS-01", "Data protection", chk_s3_encrypt),
    Rule("IAM-004", "Access key older than 90 days", "Medium", "IAM",
         "Long-lived keys increase the window for misuse if leaked.",
         "1.13", "PR.AA-01", "Identity and access management", chk_key_age),
    Rule("EC2-002", "EBS volume not encrypted", "Medium", "Storage",
         "Unencrypted volumes and snapshots expose data if copied or shared.",
         "5.1.1", "PR.DS-01", "Data protection", chk_ebs),
    Rule("RDS-002", "RDS instance not encrypted", "Medium", "Database",
         "Unencrypted database storage and backups weaken data protection.",
         "2.2.1", "PR.DS-01", "Data protection", chk_rds_encrypt),
    Rule("S3-003", "S3 versioning disabled", "Low", "Storage",
         "No versioning means deletions or overwrites cannot be recovered.",
         "n/a", "PR.DS-11", "Data protection", chk_s3_version),
]