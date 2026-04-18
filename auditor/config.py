from __future__ import annotations

import os
from pathlib import Path

from auditor.models import GitLabConnection


def load_dotenv(dotenv_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not dotenv_path.exists():
        return values

    for raw_line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip().strip('"').strip("'")
    return values


def app_env(root: Path) -> dict[str, str]:
    values = dict(os.environ)
    values.update(load_dotenv(root / ".env"))
    return values


def gitlab_connection_from_env(values: dict[str, str]) -> GitLabConnection:
    limit = 5
    raw_limit = values.get("GITLAB_PIPELINE_LIMIT", "").strip()
    if raw_limit.isdigit():
        limit = max(1, min(20, int(raw_limit)))

    return GitLabConnection(
        base_url=values.get("GITLAB_BASE_URL", "").strip(),
        project=values.get("GITLAB_PROJECT", "").strip(),
        token=values.get("GITLAB_TOKEN", "").strip(),
        ref=values.get("GITLAB_REF", "").strip(),
        pipeline_limit=limit,
    )
