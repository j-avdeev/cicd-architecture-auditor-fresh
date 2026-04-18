from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from auditor.models import Finding, ProjectContext, RemediationResult


CODEX_CMD = r"C:\Users\j-avd\AppData\Roaming\npm\codex.cmd"


def remediation_prompt(
    findings: list[Finding],
    target_path: Path,
    context: ProjectContext,
    mode: str,
) -> str:
    heading = "You are fixing CI/CD issues" if len(findings) > 1 else "You are fixing a CI/CD issue"
    lines = [
        f"{heading} in the repository at: {target_path}",
        "",
        f"Mode: {mode}",
    ]
    if len(findings) == 1:
        finding = findings[0]
        lines.extend(
            [
                f"Finding: {finding.title}",
                f"Severity: {finding.severity}",
                f"Dimension: {finding.dimension}",
                f"Summary: {finding.summary}",
                f"Impact: {finding.impact}",
                f"Recommendation: {finding.recommendation}",
            ]
        )
    else:
        lines.append(f"Selected findings: {len(findings)}")
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    "",
                    f"{index}. {finding.title}",
                    f"   Severity: {finding.severity}",
                    f"   Dimension: {finding.dimension}",
                    f"   Summary: {finding.summary}",
                    f"   Impact: {finding.impact}",
                    f"   Recommendation: {finding.recommendation}",
                ]
            )
    if context.description:
        lines.append(f"Project context: {context.description}")
    if context.stack:
        lines.append(f"Stack: {context.stack}")
    if context.goals:
        lines.append(f"Desired outcome: {context.goals}")
    for finding in findings:
        if not finding.evidence:
            continue
        lines.append(f"Evidence for {finding.title}:")
        for evidence in finding.evidence:
            line_ref = f":{evidence.line}" if evidence.line else ""
            lines.append(f"- {evidence.path}{line_ref} -> {evidence.snippet}")
    lines.extend(
        [
            "",
            "Instructions:",
            "- Inspect the repository before changing files.",
            "- Keep the fix tightly scoped to the selected findings unless a nearby supporting change is necessary.",
            "- Consolidate related edits where that reduces CI/CD duplication or improves maintainability.",
            "- If mode is 'plan', do not modify files; explain the exact change you would make.",
            "- If mode is 'apply', make the code changes directly in the repository.",
            "- Mention the files you changed or would change.",
        ]
    )
    return "\n".join(lines)


def execute_codex_for_findings(
    target_path: Path,
    findings: list[Finding],
    context: ProjectContext,
    mode: str,
    on_log: Callable[[str], None] | None = None,
    on_process_start: Callable[[int], None] | None = None,
) -> RemediationResult:
    if not target_path.exists():
        return RemediationResult(
            mode=mode,
            finding_title=findings[0].title if findings else "No findings selected",
            target_path=str(target_path),
            command="",
            success=False,
            message=f"Target path does not exist: {target_path}",
            finding_count=len(findings),
        )
    if not findings:
        return RemediationResult(
            mode=mode,
            finding_title="No findings selected",
            target_path=str(target_path),
            command="",
            success=False,
            message="Select at least one finding before starting Codex remediation.",
            finding_count=0,
        )

    prompt = remediation_prompt(findings, target_path, context, mode)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as last_message_file:
        last_message_path = Path(last_message_file.name)

    command = [
        "cmd",
        "/c",
        CODEX_CMD,
        "exec",
        "--skip-git-repo-check",
        "--output-last-message",
        str(last_message_path),
        "-C",
        str(target_path),
    ]

    if mode == "apply":
        command.append("--full-auto")
    else:
        command.extend(["-s", "read-only"])

    command.append(prompt)

    if on_log is not None:
        on_log(f"[auditor] Launching Codex in {mode} mode for {len(findings)} finding(s).")
        on_log(f"[auditor] Target repo: {target_path}")
        on_log("[auditor] Inspecting repository and starting Codex...")

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    if on_process_start is not None:
        on_process_start(process.pid)
    output_parts: list[str] = []
    assert process.stdout is not None
    for line in process.stdout:
        output_parts.append(line)
        if on_log is not None:
            on_log(line.rstrip())
    return_code = process.wait(timeout=600)

    last_message = ""
    if last_message_path.exists():
        last_message = last_message_path.read_text(encoding="utf-8", errors="ignore").strip()
        last_message_path.unlink(missing_ok=True)

    raw_output = "".join(output_parts)
    success = return_code == 0
    message = "Codex completed successfully." if success else f"Codex exited with code {return_code}."
    if on_log is not None:
        on_log(f"[auditor] {message}")
    label = findings[0].title if len(findings) == 1 else f"{len(findings)} findings"
    return RemediationResult(
        mode=mode,
        finding_title=label,
        target_path=str(target_path),
        command=" ".join(command[:8]) + " ...",
        success=success,
        message=message,
        finding_count=len(findings),
        last_message=last_message,
        raw_output=raw_output[-12000:],
    )


def run_codex_for_findings(
    target_path: Path,
    findings: list[Finding],
    context: ProjectContext,
    mode: str,
) -> RemediationResult:
    return execute_codex_for_findings(target_path, findings, context, mode, on_log=None)


def run_codex_for_finding(
    target_path: Path,
    finding: Finding,
    context: ProjectContext,
    mode: str,
) -> RemediationResult:
    return run_codex_for_findings(target_path, [finding], context, mode)
