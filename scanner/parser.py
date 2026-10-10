"""Load an exported AWS configuration file (JSON or YAML) into a Python dict."""
import json
from pathlib import Path

import yaml


def load_config(path):
    """Read a .json / .yaml / .yml file and return the config as a dict.

    Raises ValueError with a readable message if the file type is unsupported
    or the content is not a valid configuration object.
    """
    p = Path(path)
    if not p.exists():
        raise ValueError(f"File not found: {p}")

    suffix = p.suffix.lower()
    text = p.read_text(encoding="utf-8")
    try:
        if suffix == ".json":
            data = json.loads(text)
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        else:
            raise ValueError(f"Unsupported file type '{suffix}'. Use .json, .yaml or .yml")
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        raise ValueError(f"Could not parse {p.name}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"{p.name} must contain a top-level object (key/value pairs).")
    return data
