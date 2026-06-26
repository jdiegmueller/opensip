"""Minimal .env loader (no external dependency)."""

from __future__ import annotations

import os
from pathlib import Path


def load_env(path: str | os.PathLike | None = None) -> None:
    """Load KEY=VALUE pairs from a .env file into os.environ if present."""
    candidates = []
    if path:
        candidates.append(Path(path))
    here = Path(__file__).resolve().parent
    candidates.extend([here / ".env", Path.cwd() / ".env"])
    for p in candidates:
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)
        return
