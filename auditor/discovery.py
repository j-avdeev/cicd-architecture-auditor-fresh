from __future__ import annotations

from pathlib import Path

from auditor.models import SourceFile


KNOWN_FILES = {
    ".gitlab-ci.yml": "gitlab",
    "Jenkinsfile": "jenkins",
    ".circleci/config.yml": "circleci",
}


def discover_ci_files(target: Path) -> list[SourceFile]:
    files: list[SourceFile] = []

    for path in target.rglob("*"):
        if not path.is_file():
            continue

        normalized = path.relative_to(target).as_posix()
        kind = None

        if normalized.startswith(".github/workflows/") and normalized.endswith((".yml", ".yaml")):
            kind = "github"
        elif normalized in KNOWN_FILES:
            kind = KNOWN_FILES[normalized]
        elif normalized.endswith((".jenkins.yaml", "jenkins.yaml", "jcasc.yaml", "casc.yaml")):
            kind = "jenkins_casc"

        if kind is None:
            continue

        files.append(SourceFile(path=path, kind=kind, text=path.read_text(encoding="utf-8", errors="ignore")))

    return sorted(files, key=lambda item: item.path.as_posix())
