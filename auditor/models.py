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
