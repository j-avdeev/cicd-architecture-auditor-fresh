from __future__ import annotations

import html
from collections import defaultdict
from pathlib import Path

from auditor.models import AnalysisResult, Finding, ProjectContext, RecentRuns, RemediationResult


def markdown_report(result: AnalysisResult) -> str:
    lines: list[str] = []
    lines.append("# CI/CD Architecture Auditor Report")
    lines.append("")
    lines.append(f"- Target: `{result.target}`")
    lines.append(f"- CI files analyzed: `{len(result.files)}`")
    lines.append(f"- Findings: `{len(result.findings)}`")
    lines.append(f"- Overall score: `{result.overall_score}/100`")
    lines.append("")
    lines.append("## Executive Scorecard")
    lines.append("")
    for dimension, score in result.scores.items():
        lines.append(f"- {dimension.title()}: `{score}/100`")
    lines.append("")
    lines.append("## Strengths")
    lines.append("")
    for strength in result.strengths:
        lines.append(f"- {strength}")
    lines.append("")
    lines.append("## Discovery Debug")
    lines.append("")
    for note in result.debug_notes:
        lines.append(f"- {note}")
    lines.append("")
    lines.append("## Top Findings")
    lines.append("")

    if not result.findings:
        lines.append("No high-signal CI/CD architecture findings were detected by the MVP rule set.")
    else:
        for finding in result.findings:
            lines.extend(render_markdown_finding(finding))

    if result.recent_runs is not None:
        lines.append("## Recent Run Evidence")
        lines.append("")
        lines.extend(render_markdown_recent_runs(result.recent_runs))

    lines.append("## Migration Plan")
    lines.append("")
    for phase, items in group_by_phase(result.findings).items():
        lines.append(f"### {phase}")
        lines.append("")
        if not items:
            lines.append("- No actions scheduled in this phase.")
        for finding in items:
            lines.append(f"- {finding.recommendation}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def render_markdown_finding(finding: Finding) -> list[str]:
    lines = [
        f"### [{finding.severity.upper()}] {finding.title}",
        "",
        f"- Dimension: `{finding.dimension}`",
        f"- Rule: `{finding.rule_id}`",
        f"- Confidence: `{finding.confidence}`",
        f"- Summary: {finding.summary}",
        f"- Impact: {finding.impact}",
        f"- Recommendation: {finding.recommendation}",
    ]
    if finding.framework_refs:
        lines.append(f"- Framework mapping: {', '.join(finding.framework_refs)}")
    if finding.evidence:
        lines.append("- Evidence:")
        for evidence in finding.evidence:
            line_ref = f":{evidence.line}" if evidence.line else ""
            lines.append(f"  - `{evidence.path}{line_ref}` -> `{evidence.snippet}`")
    lines.append("")
    return lines


def html_report(result: AnalysisResult, context: ProjectContext | None = None, build_label: str = "") -> str:
    content = report_fragment(result, context=context, build_label=build_label)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CI/CD Architecture Auditor Report</title>
  {base_styles()}
</head>
<body>
{content}
{base_script()}
</body>
</html>
"""


def report_fragment(
    result: AnalysisResult,
    context: ProjectContext | None = None,
    build_label: str = "",
    display_target: str | None = None,
    remediation_target: str = "",
    remediation_result: RemediationResult | None = None,
) -> str:
    cards = "".join(
        f"<div class='card'><h3>{html.escape(dimension.title())}</h3><p>{score}/100</p></div>"
        for dimension, score in result.scores.items()
    )
    findings_body = "".join(
        render_html_finding(
            finding,
            remediation_target=remediation_target,
            context=context,
        )
        for finding in result.findings
    ) or "<p>No findings.</p>"
    findings = render_findings_panel(findings_body, result.findings, remediation_target, context)
    phases = []
    for phase, items in group_by_phase(result.findings).items():
        phase_items = "".join(render_migration_item(phase, item.recommendation) for item in items) or "<li>No actions scheduled.</li>"
        phases.append(f"<section><h3>{html.escape(phase)}</h3><ul>{phase_items}</ul></section>")

    strengths = "".join(f"<li>{html.escape(item)}</li>" for item in result.strengths)
    debug = "".join(f"<li>{html.escape(item)}</li>" for item in result.debug_notes)
    context_section = render_context_panel(context)
    build_badge = f"<span class='build-badge'>{html.escape(build_label)}</span>" if build_label else ""
    recent_runs_section = render_recent_runs_panel(result.recent_runs)
    remediation_section = render_remediation_panel(remediation_result)
    target_label = display_target or str(result.target)
    return f"""
  <main class="report-shell">
    <section class="hero">
      <div class="hero-topline">
        <h1>CI/CD Architecture Auditor</h1>
        {build_badge}
      </div>
      <p class="muted">Target: {html.escape(target_label)}</p>
      <p>Overall score: <strong>{result.overall_score}/100</strong> across {len(result.files)} CI files and {len(result.findings)} findings.</p>
    </section>
    {context_section}
    {remediation_section}
    <section class="panel">
      <h2>Executive Scorecard</h2>
      <div class="grid">{cards}</div>
    </section>
    <section class="panel">
      <h2>Strengths</h2>
      <ul>{strengths}</ul>
    </section>
    <section class="panel">
      <h2>Discovery Debug</h2>
      <ul>{debug}</ul>
    </section>
    {findings}
    {recent_runs_section}
    <section class="panel">
      <h2>Migration Plan</h2>
      {''.join(phases)}
    </section>
  </main>
"""


def base_styles() -> str:
    return """<style>
    :root {
      --bg: #f4efe6;
      --panel: #fffdf8;
      --ink: #1f2933;
      --muted: #52606d;
      --accent: #0f766e;
      --warn: #b91c1c;
      --border: #d9d1c3;
    }
    body {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      background:
        radial-gradient(circle at top right, rgba(15,118,110,.12), transparent 25%),
        linear-gradient(180deg, #f9f5ee, var(--bg));
      color: var(--ink);
    }
    main {
      max-width: 1100px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }
    .hero, .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 22px;
      box-shadow: 0 10px 30px rgba(31,41,51,.07);
      margin-bottom: 20px;
    }
    h1, h2, h3 { margin-top: 0; }
    .hero-topline {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .build-badge {
      display: inline-block;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 6px 12px;
      font-size: .85rem;
      background: #fff;
      color: var(--muted);
    }
    .muted { color: var(--muted); }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
    }
    .card {
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
      background: #fff;
    }
    .finding {
      border-left: 6px solid var(--accent);
      margin-bottom: 14px;
      position: relative;
    }
    .severity-critical, .severity-high {
      border-left-color: var(--warn);
    }
    .finding-topline {
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 12px;
    }
    .copy-button {
      border: 1px solid var(--border);
      background: #fff;
      color: var(--ink);
      border-radius: 999px;
      padding: 8px 12px;
      font: inherit;
      cursor: pointer;
      white-space: nowrap;
    }
    .copy-button:hover {
      background: #f8f4ec;
    }
    .action-cluster {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: center;
    }
    .action-form {
      margin: 0;
    }
    .bulk-actions {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 16px;
    }
    .bulk-left {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }
    .bulk-note {
      color: var(--muted);
      font-size: .95rem;
    }
    .action-button {
      border: 1px solid var(--border);
      background: #f3fbf9;
      color: var(--ink);
      border-radius: 999px;
      padding: 8px 12px;
      font: inherit;
      cursor: pointer;
      white-space: nowrap;
    }
    .action-button.apply {
      background: #0f766e;
      color: #fff;
      border-color: #0f766e;
    }
    .finding-note {
      margin-top: 10px;
      color: var(--muted);
      font-size: .92rem;
    }
    .finding-check {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-right: auto;
      color: var(--muted);
      font-size: .95rem;
      white-space: nowrap;
    }
    .migration-item {
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 12px;
      margin-bottom: 10px;
    }
    .review-panel {
      border-color: #0f766e;
      background: #f4fbf9;
    }
    .console-panel {
      border-color: #1f2933;
      background: #fbfaf7;
    }
    .console-meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 12px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 6px 12px;
      background: #ece6da;
      color: var(--ink);
      font-size: .92rem;
    }
    .approval-note {
      color: #8a5200;
      font-weight: bold;
    }
    .migration-copy {
      flex: 0 0 auto;
      padding: 6px 10px;
      font-size: .92rem;
    }
    ul { padding-left: 20px; }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      background: #f6f2ea;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      overflow-x: auto;
    }
    code {
      background: #f1ede5;
      padding: 2px 5px;
      border-radius: 4px;
    }
  </style>"""


def base_script() -> str:
    return """<script>
document.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-copy-text]');
  if (button) {
    const text = button.getAttribute('data-copy-text') || '';
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = 'Copied';
      setTimeout(() => {
        button.textContent = original;
      }, 1200);
    } catch (error) {
      button.textContent = 'Copy failed';
      setTimeout(() => {
        button.textContent = original;
      }, 1600);
    }
    return;
  }

  const selectionButton = event.target.closest('[data-select-findings]');
  if (selectionButton) {
    const mode = selectionButton.getAttribute('data-select-findings');
    document.querySelectorAll('.batch-finding-select').forEach((checkbox) => {
      checkbox.checked = mode === 'all';
    });
  }
});

document.addEventListener('submit', (event) => {
  const form = event.target.closest('form[data-batch-remediation]');
  if (!form) return;

  form.querySelectorAll('input[name="selected_finding"]').forEach((node) => node.remove());
  const checked = Array.from(document.querySelectorAll('.batch-finding-select:checked'));
  checked.forEach((checkbox) => {
    const hidden = document.createElement('input');
    hidden.type = 'hidden';
    hidden.name = 'selected_finding';
    hidden.value = checkbox.value;
    form.appendChild(hidden);
  });
});

async function pollRemediationJob(panel) {
  const jobId = panel.getAttribute('data-remediation-job');
  if (!jobId) return;
  try {
    const response = await fetch(`/job-status?id=${encodeURIComponent(jobId)}`);
    if (!response.ok) return;
    const payload = await response.json();
    panel.querySelectorAll('[data-job-field]').forEach((node) => {
      const field = node.getAttribute('data-job-field');
      const value = payload[field];
      if (field === 'logs') {
        node.textContent = value || '';
      } else {
        node.textContent = value == null ? '' : String(value);
      }
    });
    if (payload.status === 'queued' || payload.status === 'running') {
      window.setTimeout(() => pollRemediationJob(panel), 1500);
    }
  } catch (error) {
    window.setTimeout(() => pollRemediationJob(panel), 2500);
  }
}

document.querySelectorAll('[data-remediation-job]').forEach((panel) => {
  pollRemediationJob(panel);
});
</script>"""


def render_findings_panel(
    findings_html: str,
    findings: list[Finding],
    remediation_target: str,
    context: ProjectContext | None,
) -> str:
    batch_controls = render_batch_actions(findings, remediation_target, context)
    return f"""
    <section class="panel">
      <h2>Top Findings</h2>
      {batch_controls}
      {findings_html}
    </section>
"""


def render_context_panel(context: ProjectContext | None) -> str:
    if context is None:
        return ""

    entries = context.entries()
    if not entries:
        return ""

    items = "".join(
        f"<div class='card'><h3>{html.escape(label)}</h3><p>{html.escape(value)}</p></div>"
        for label, value in entries
    )
    return f"""
    <section class="panel">
      <h2>Project Context</h2>
      <div class="grid">{items}</div>
    </section>
"""


def render_recent_runs_panel(recent_runs: RecentRuns | None) -> str:
    if recent_runs is None:
        return ""

    pipeline_cards = []
    for pipeline in recent_runs.pipelines[:5]:
        duration = f"{pipeline.duration_seconds:.1f}s" if pipeline.duration_seconds is not None else "unknown"
        pipeline_cards.append(
            f"<div class='card'><h3>Pipeline #{pipeline.pipeline_id}</h3>"
            f"<p><strong>Status:</strong> {html.escape(pipeline.status)}</p>"
            f"<p><strong>Ref:</strong> {html.escape(pipeline.ref)}</p>"
            f"<p><strong>Duration:</strong> {html.escape(duration)}</p>"
            f"<p><strong>Updated:</strong> {html.escape(pipeline.updated_at)}</p></div>"
        )
    notes = "".join(f"<li>{html.escape(note)}</li>" for note in recent_runs.summary_notes)
    return f"""
    <section class="panel">
      <h2>Recent Run Evidence</h2>
      <p class="muted">Connected provider: {html.escape(recent_runs.provider)} | project: {html.escape(recent_runs.project_label)} | fetched pipelines: {recent_runs.fetched_count}</p>
      <ul>{notes}</ul>
      <div class="grid">{''.join(pipeline_cards)}</div>
    </section>
""" 


def render_html_finding(
    finding: Finding,
    remediation_target: str = "",
    context: ProjectContext | None = None,
) -> str:
    evidence_items = "".join(
        f"<li><code>{html.escape(evidence.path)}{':' + str(evidence.line) if evidence.line else ''}</code> - {html.escape(evidence.snippet)}</li>"
        for evidence in finding.evidence
    )
    refs = ", ".join(finding.framework_refs)
    copy_text = html.escape(finding_copy_text(finding), quote=True)
    actions = render_finding_actions(finding, remediation_target, context)
    check = render_finding_checkbox(finding, remediation_target)
    return f"""
<article class="card finding severity-{html.escape(finding.severity)}">
  <div class="finding-topline">
    <h3>[{html.escape(finding.severity.upper())}] {html.escape(finding.title)}</h3>
    <div class="action-cluster">
      {check}
      <button class="copy-button" type="button" data-copy-text="{copy_text}">Copy</button>
      {actions}
    </div>
  </div>
  <p><strong>Dimension:</strong> {html.escape(finding.dimension.title())} | <strong>Rule:</strong> {html.escape(finding.rule_id)} | <strong>Confidence:</strong> {html.escape(finding.confidence)}</p>
  <p><strong>Summary:</strong> {html.escape(finding.summary)}</p>
  <p><strong>Impact:</strong> {html.escape(finding.impact)}</p>
  <p><strong>Recommendation:</strong> {html.escape(finding.recommendation)}</p>
  <p><strong>Framework mapping:</strong> {html.escape(refs or 'None')}</p>
  <ul>{evidence_items}</ul>
</article>
"""


def render_finding_actions(
    finding: Finding,
    remediation_target: str,
    context: ProjectContext | None,
) -> str:
    if not remediation_target:
        return "<span class='finding-note'>Codex actions are available for local path analysis.</span>"

    context = context or ProjectContext()
    hidden = remediation_hidden_inputs(finding, remediation_target, context)
    plan_form = (
        "<form class='action-form' method='post' action='/remediation-review'>"
        f"{hidden}"
        "<input type='hidden' name='mode' value='plan'>"
        "<button class='action-button' type='submit'>Plan with Codex</button>"
        "</form>"
    )
    apply_form = (
        "<form class='action-form' method='post' action='/remediation-review'>"
        f"{hidden}"
        "<input type='hidden' name='mode' value='apply'>"
        "<button class='action-button apply' type='submit'>Fix with Codex</button>"
        "</form>"
    )
    return plan_form + apply_form


def render_batch_actions(
    findings: list[Finding],
    remediation_target: str,
    context: ProjectContext | None,
) -> str:
    if not findings:
        return ""
    if not remediation_target:
        return "<p class='bulk-note'>Batch Codex actions are available for local path analysis.</p>"

    context = context or ProjectContext()
    shared_hidden = remediation_context_inputs(remediation_target, context)
    controls = (
        "<form id='batch-plan-form' class='bulk-actions' method='post' action='/remediation-review' data-batch-remediation='true'>"
        "<div class='bulk-left'>"
        "<button class='action-button' type='button' data-select-findings='all'>Select all</button>"
        "<button class='action-button' type='button' data-select-findings='none'>Clear</button>"
        "<span class='bulk-note'>Choose one or more findings, then send the group to Codex.</span>"
        "</div>"
        "<div class='bulk-left'>"
        f"{shared_hidden}"
        "<input type='hidden' name='mode' value='plan'>"
        "<button class='action-button' type='submit'>Plan selected with Codex</button>"
        "</div>"
        "</form>"
        "<form id='batch-apply-form' class='bulk-actions' method='post' action='/remediation-review' data-batch-remediation='true'>"
        "<div class='bulk-left'></div>"
        "<div class='bulk-left'>"
        f"{shared_hidden}"
        "<input type='hidden' name='mode' value='apply'>"
        "<button class='action-button apply' type='submit'>Fix selected with Codex</button>"
        "</div>"
        "</form>"
    )
    return controls


def remediation_context_inputs(remediation_target: str, context: ProjectContext) -> str:
    values = {
        "target_path": remediation_target,
        "project_description": context.description,
        "project_stack": context.stack,
        "project_goals": context.goals,
    }
    return "".join(
        f"<input type='hidden' name='{html.escape(name)}' value='{html.escape(value, quote=True)}'>"
        for name, value in values.items()
    )


def render_finding_checkbox(finding: Finding, remediation_target: str) -> str:
    if not remediation_target:
        return ""
    key = html.escape(finding_key(finding), quote=True)
    return (
        "<label class='finding-check'>"
        f"<input class='batch-finding-select' type='checkbox' value='{key}'>"
        "Select"
        "</label>"
    )


def remediation_hidden_inputs(finding: Finding, remediation_target: str, context: ProjectContext) -> str:
    values = {
        "target_path": remediation_target,
        "selected_finding": finding_key(finding),
        "project_description": context.description,
        "project_stack": context.stack,
        "project_goals": context.goals,
    }
    return "".join(
        f"<input type='hidden' name='{html.escape(name)}' value='{html.escape(value, quote=True)}'>"
        for name, value in values.items()
    )


def finding_key(finding: Finding) -> str:
    return f"{finding.rule_id}|{finding.title}"


def render_remediation_panel(remediation_result: RemediationResult | None) -> str:
    if remediation_result is None:
        return ""

    status = "Success" if remediation_result.success else "Needs attention"
    accent = "var(--accent)" if remediation_result.success else "var(--warn)"
    last_message = (
        f"<div class='card'><h3>Codex summary</h3><pre>{html.escape(remediation_result.last_message)}</pre></div>"
        if remediation_result.last_message
        else ""
    )
    raw_output = (
        f"<div class='card'><h3>Runner output</h3><pre>{html.escape(remediation_result.raw_output)}</pre></div>"
        if remediation_result.raw_output
        else ""
    )
    return f"""
    <section class="panel">
      <h2>Codex Remediation</h2>
      <p><strong>Status:</strong> <span style="color:{accent};">{html.escape(status)}</span></p>
      <p><strong>Mode:</strong> {html.escape(remediation_result.mode)} | <strong>Target:</strong> {html.escape(remediation_result.finding_title)}</p>
      <p><strong>Selected findings:</strong> {remediation_result.finding_count}</p>
      <p><strong>Repo:</strong> {html.escape(remediation_result.target_path)}</p>
      <p><strong>Command:</strong> <code>{html.escape(remediation_result.command)}</code></p>
      <p>{html.escape(remediation_result.message)}</p>
      {last_message}
      {raw_output}
    </section>
"""


def finding_copy_text(finding: Finding) -> str:
    lines = [
        "Please improve this repo based on the CI/CD finding below.",
        "",
        f"Finding: {finding.title}",
        f"Severity: {finding.severity}",
        f"Dimension: {finding.dimension}",
        f"Summary: {finding.summary}",
        f"Impact: {finding.impact}",
        f"Recommendation: {finding.recommendation}",
    ]
    if finding.framework_refs:
        lines.append(f"Framework mapping: {', '.join(finding.framework_refs)}")
    if finding.evidence:
        lines.append("Evidence:")
        for evidence in finding.evidence:
            line_ref = f":{evidence.line}" if evidence.line else ""
            lines.append(f"- {evidence.path}{line_ref} -> {evidence.snippet}")
    lines.append("")
    lines.append("Please propose concrete repository changes and, if appropriate, patch the CI/CD files or helper scripts.")
    return "\n".join(lines)


def render_markdown_recent_runs(recent_runs: RecentRuns) -> list[str]:
    lines = [
        f"- Provider: `{recent_runs.provider}`",
        f"- Project: `{recent_runs.project_label}`",
        f"- Pipelines fetched: `{recent_runs.fetched_count}`",
    ]
    for note in recent_runs.summary_notes:
        lines.append(f"- {note}")
    lines.append("")
    for pipeline in recent_runs.pipelines[:5]:
        duration = f"{pipeline.duration_seconds:.1f}s" if pipeline.duration_seconds is not None else "unknown"
        lines.append(f"### Pipeline #{pipeline.pipeline_id}")
        lines.append("")
        lines.append(f"- Status: `{pipeline.status}`")
        lines.append(f"- Ref: `{pipeline.ref}`")
        lines.append(f"- Duration: `{duration}`")
        lines.append(f"- Updated: `{pipeline.updated_at}`")
        if pipeline.jobs:
            lines.append("- Jobs:")
            for job in pipeline.jobs[:5]:
                qd = f", queued {job.queued_duration_seconds:.1f}s" if job.queued_duration_seconds is not None else ""
                dd = f", duration {job.duration_seconds:.1f}s" if job.duration_seconds is not None else ""
                lines.append(f"  - `{job.stage}/{job.name}` -> `{job.status}{dd}{qd}`")
        lines.append("")
    return lines


def render_migration_item(phase: str, recommendation: str) -> str:
    copy_text = html.escape(migration_copy_text(phase, recommendation), quote=True)
    return (
        "<li class='migration-item'>"
        f"<span>{html.escape(recommendation)}</span>"
        f"<button class='copy-button migration-copy' type='button' data-copy-text=\"{copy_text}\">Copy</button>"
        "</li>"
    )


def migration_copy_text(phase: str, recommendation: str) -> str:
    lines = [
        "Please improve this repo based on the CI/CD migration action below.",
        "",
        f"Phase: {phase}",
        f"Action: {recommendation}",
        "",
        "Please propose concrete repository changes and, if appropriate, patch the CI/CD files or helper scripts to implement this migration step.",
    ]
    return "\n".join(lines)


def group_by_phase(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    seen_by_phase: dict[str, set[str]] = defaultdict(set)
    for phase in ["Phase A: Hardening", "Phase B: Standardization", "Phase C: Scale Optimization"]:
        grouped[phase] = []
    for finding in findings:
        if finding.recommendation in seen_by_phase[finding.phase]:
            continue
        seen_by_phase[finding.phase].add(finding.recommendation)
        grouped[finding.phase].append(finding)
    return grouped


def write_reports(result: AnalysisResult, output_dir: Path, html_enabled: bool = True) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    md_path = output_dir / "report.md"
    md_path.write_text(markdown_report(result), encoding="utf-8")
    paths.append(md_path)

    if html_enabled:
        html_path = output_dir / "report.html"
        html_path.write_text(html_report(result), encoding="utf-8")
        paths.append(html_path)

    return paths
