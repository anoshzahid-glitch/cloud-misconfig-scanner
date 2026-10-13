"""Scan-time test on synthetic configs of increasing size (every 3rd resource misconfigured)."""
import time
from scanner.engine import scan


def make_config(n):
    return {
        "account": {"root_mfa_enabled": True, "root_access_keys": 0},
        "s3_buckets": [{"name": f"b{i}", "public_access_block": i % 3 != 0, "encryption": True, "versioning": True} for i in range(n)],
        "security_groups": [{"id": f"sg{i}", "ingress": [{"from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0" if i % 3 == 0 else "10.0.0.0/8"}]} for i in range(n)],
        "iam_users": [{"name": f"u{i}", "console_access": True, "mfa_enabled": i % 3 != 0, "access_key_age_days": 10} for i in range(n)],
        "iam_policies": [], "cloudtrail": {"enabled": True, "multi_region": True},
        "ebs_volumes": [{"id": f"v{i}", "encrypted": i % 3 != 0} for i in range(n)],
        "rds_instances": [{"id": f"d{i}", "publicly_accessible": False, "encrypted": i % 3 != 0} for i in range(n)],
    }


if __name__ == "__main__":
    print(f"{'resources':>10} {'findings':>9} {'scan ms':>9}")
    for n in (10, 100, 1000, 10000, 50000):
        cfg = make_config(n)
        resources = n * 5
        t = []
        for _ in range(5):
            s = time.perf_counter(); res = scan(cfg); t.append((time.perf_counter() - s) * 1000)
        print(f"{resources:>10} {len(res):>9} {sorted(t)[2]:>9.2f}")
