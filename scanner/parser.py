"""Load an exported AWS configuration file (JSON or YAML) into a Python dict."""
import json
from pathlib import Path

import yaml


def parse_text(text, suffix, name="config"):
    """Parse JSON/YAML text. `suffix` is '.json', '.yaml' or '.yml'.

    Raises ValueError with a readable message on unsupported or invalid input.
    """
    suffix = suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(text)
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        else:
            raise ValueError(f"Unsupported file type '{suffix}'. Use .json, .yaml or .yml")
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        raise ValueError(f"Could not parse {name}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"{name} must contain a top-level object (key/value pairs).")
    return data


def load_config(path):
    """Read a config file from disk and return it as a dict."""
    p = Path(path)
    if not p.exists():
        raise ValueError(f"File not found: {p}")
    return parse_text(p.read_text(encoding="utf-8"), p.suffix, p.name)
