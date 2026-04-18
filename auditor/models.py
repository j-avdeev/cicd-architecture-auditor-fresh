from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


DIMENSIONS = ["security", "reliability", "maintainability", "scalability", "cost"]
WEIGHTS = {
    "security": 30,
    "reliability": 25,
    "maintainability": 20,
    "scalability": 15,
    "cost": 10,
}
SEVERITY_POINTS = {"critical": 16, "high": 10, "medium": 6, "low": 3}


@dataclass
class Evidence:
    path: str
    line: int | None
    snippet: str


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    dimension: str
    summary: str
    impact: str
    recommendation: str
    phase: str
    confidence: str = "medium"
    framework_refs: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def points(self) -> int:
        return SEVERITY_POINTS[self.severity]


@dataclass
class SourceFile:
    path: Path
    kind: str
    text: str

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass
class AnalysisResult:
    target: Path
    files: list[SourceFile]
    findings: list[Finding]
    scores: dict[str, int]
    overall_score: int
    strengths: list[str]
    debug_notes: list[str]
    recent_runs: "RecentRuns | None" = None


@dataclass
class ProjectContext:
    description: str = ""
    stack: str = ""
    goals: str = ""

    def entries(self) -> list[tuple[str, str]]:
        items = [
            ("Project", self.description.strip()),
            ("Stack", self.stack.strip()),
            ("Wanted Outcome", self.goals.strip()),
        ]
        return [(label, value) for label, value in items if value]

    def as_dict(self) -> dict[str, str]:
        return {
            "description": self.description,
            "stack": self.stack,
            "goals": self.goals,
        }


@dataclass
class GitLabConnection:
    base_url: str = ""
    project: str = ""
    token: str = ""
    ref: str = ""
    pipeline_limit: int = 5

    @property
    def enabled(self) -> bool:
        return bool(self.base_url.strip() and self.project.strip() and self.token.strip())

    def as_public_dict(self) -> dict[str, str | int]:
        return {
            "base_url": self.base_url,
            "project": self.project,
            "ref": self.ref,
            "pipeline_limit": self.pipeline_limit,
        }


@dataclass
class GitLabJobRun:
    name: str
    stage: str
    status: str
    duration_seconds: float | None = None
    queued_duration_seconds: float | None = None
    web_url: str = ""


@dataclass
class GitLabPipelineRun:
    pipeline_id: int
    status: str
    ref: str
    sha: str
    created_at: str
    updated_at: str
    web_url: str = ""
    duration_seconds: float | None = None
    jobs: list[GitLabJobRun] = field(default_factory=list)


@dataclass
class RecentRuns:
    provider: str
    project_label: str
    fetched_count: int
    pipelines: list[GitLabPipelineRun] = field(default_factory=list)
    summary_notes: list[str] = field(default_factory=list)


@dataclass
class SavedContext:
    target_path: str = ""
    project_context: ProjectContext = field(default_factory=ProjectContext)
    gitlab_connection: GitLabConnection = field(default_factory=GitLabConnection)

    def as_dict(self) -> dict[str, object]:
        return {
            "target_path": self.target_path,
            "project_context": self.project_context.as_dict(),
            "gitlab": self.gitlab_connection.as_public_dict(),
        }


@dataclass
class RemediationResult:
    mode: str
    finding_title: str
    target_path: str
    command: str
    success: bool
    message: str
    finding_count: int = 1
    last_message: str = ""
    raw_output: str = ""
