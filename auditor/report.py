from __future__ import annotations

import html
from collections import defaultdict
from pathlib import Path

from auditor.models import AnalysisResult, Finding, ProjectContext, RemediationResult


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
    remediation_inputs: str = "",
    remediation_enabled: bool = False,
    remediation_result: RemediationResult | None = None,
) -> str:
    cards = "".join(
        f"<div class='card'><h3>{html.escape(dimension.title())}</h3><p>{score}/100</p></div>"
        for dimension, score in result.scores.items()
    )
    findings_body = "".join(
        render_html_finding(
            finding,
            remediation_inputs=remediation_inputs,
            remediation_enabled=remediation_enabled,
        )
        for finding in result.findings
    ) or "<p>No findings.</p>"
    findings = render_findings_panel(findings_body)
    phases = []
    for phase, items in group_by_phase(result.findings).items():
        phase_items = "".join(render_migration_item(phase, item.recommendation) for item in items) or "<li>No actions scheduled.</li>"
        phases.append(f"<section><h3>{html.escape(phase)}</h3><ul>{phase_items}</ul></section>")

    strengths = "".join(f"<li>{html.escape(item)}</li>" for item in result.strengths)
    debug = "".join(f"<li>{html.escape(item)}</li>" for item in result.debug_notes)
    context_section = render_context_panel(context)
    build_badge = f"<span class='build-badge'>{html.escape(build_label)}</span>" if build_label else ""
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
    .action-button {
      border: 1px solid var(--border);
      background: #fff;
      color: var(--ink);
      border-radius: 999px;
      padding: 8px 12px;
      font: inherit;
      cursor: pointer;
      white-space: nowrap;
      transition: background .16s ease, color .16s ease, border-color .16s ease;
    }
    .action-button.apply {
      background: #fff;
      color: var(--ink);
      border-color: var(--border);
    }
    .action-button.apply:hover {
      background: #f8f4ec;
    }
    .action-button.running {
      width: 42px;
      min-width: 42px;
      height: 42px;
      padding: 0;
      border-radius: 12px;
      background: #1f2933;
      border-color: #1f2933;
      color: #fff;
      font-size: 1rem;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .finding-note {
      margin-top: 10px;
      color: var(--muted);
      font-size: .92rem;
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
    .finding-console {
      margin-top: 14px;
      padding: 14px;
      border: 1px solid var(--border);
      border-radius: 14px;
      background: #fbfaf7;
    }
    .finding-console[hidden] {
      display: none;
    }
    .console-meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 12px;
    }
    .console-title {
      margin: 0 0 8px;
      font-size: 1rem;
    }
    .console-log {
      max-height: 280px;
      overflow-y: auto;
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

});

document.addEventListener('submit', async (event) => {
  const form = event.target.closest('form[data-remediation-launch]');
  if (!form) return;
  event.preventDefault();

  const button = form.querySelector('[data-remediation-button]');
  if (!button) return;

  if (button.dataset.jobId) {
    await stopRemediationJob(button.dataset.jobId, button, form);
    return;
  }

  const payload = new URLSearchParams(new FormData(form));
  button.disabled = true;
  try {
    const response = await fetch('/remediation-start-json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
      body: payload.toString(),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Could not start Codex remediation.');
    }
    activateRemediationUI(form, button, data);
  } catch (error) {
    renderInlineRemediationError(form, error instanceof Error ? error.message : 'Could not start Codex remediation.');
  } finally {
    button.disabled = false;
  }
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
    syncGlobalRemediationPanel(payload);
    syncRemediationButton(panel, payload);
    if (payload.status === 'queued' || payload.status === 'running') {
      window.setTimeout(() => pollRemediationJob(panel), 1500);
    }
  } catch (error) {
    window.setTimeout(() => pollRemediationJob(panel), 2500);
  }
}

function activateRemediationUI(form, button, payload) {
  const finding = form.closest('[data-finding-key]');
  const consolePanel = finding ? finding.querySelector('[data-inline-remediation]') : null;
  if (!consolePanel) return;
  consolePanel.hidden = false;
  consolePanel.setAttribute('data-remediation-job', payload.job_id);
  consolePanel.querySelectorAll('[data-job-field]').forEach((node) => {
    const field = node.getAttribute('data-job-field');
    const value = payload[field];
    if (field === 'logs') {
      node.textContent = value || '';
    } else {
      node.textContent = value == null ? '' : String(value);
    }
  });
  syncRemediationButton(consolePanel, payload);
  syncGlobalRemediationPanel(payload);
  pollRemediationJob(consolePanel);
}

function syncRemediationButton(panel, payload) {
  const finding = panel.closest('[data-finding-key]');
  const button = finding ? finding.querySelector('[data-remediation-button]') : null;
  if (!button) return;
  const active = payload.status === 'queued' || payload.status === 'running';
  if (active) {
    button.textContent = '■';
    button.classList.add('running');
    button.dataset.jobId = payload.job_id || panel.getAttribute('data-remediation-job') || '';
    button.title = 'Stop Codex';
  } else {
    button.textContent = 'Fix with Codex';
    button.classList.remove('running');
    button.dataset.jobId = '';
    button.title = 'Fix with Codex';
  }
}

function syncGlobalRemediationPanel(payload) {
  const panel = document.querySelector('[data-global-remediation]');
  if (!panel) return;
  panel.hidden = false;
  panel.querySelectorAll('[data-global-job-field]').forEach((node) => {
    const field = node.getAttribute('data-global-job-field');
    const value = payload[field];
    if (field === 'logs') {
      node.textContent = value || '';
    } else {
      node.textContent = value == null ? '' : String(value);
    }
  });
}

async function stopRemediationJob(jobId, button, form) {
  button.disabled = true;
  try {
    const response = await fetch('/remediation-stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
      body: new URLSearchParams({ job_id: jobId }).toString(),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Could not stop Codex remediation.');
    }
    const finding = form.closest('[data-finding-key]');
    const consolePanel = finding ? finding.querySelector('[data-inline-remediation]') : null;
    if (consolePanel) {
      consolePanel.setAttribute('data-remediation-job', jobId);
      syncRemediationButton(consolePanel, data);
      syncGlobalRemediationPanel(data);
      pollRemediationJob(consolePanel);
    }
  } catch (error) {
    renderInlineRemediationError(form, error instanceof Error ? error.message : 'Could not stop Codex remediation.');
  } finally {
    button.disabled = false;
  }
}

function renderInlineRemediationError(form, message) {
  const finding = form.closest('[data-finding-key]');
  const consolePanel = finding ? finding.querySelector('[data-inline-remediation]') : null;
  if (!consolePanel) return;
  consolePanel.hidden = false;
  consolePanel.querySelector('[data-job-field="status"]').textContent = 'error';
  consolePanel.querySelector('[data-job-field="message"]').textContent = message;
  consolePanel.querySelector('[data-job-field="logs"]').textContent = `[auditor] ${message}`;
}

document.querySelectorAll('[data-remediation-job]').forEach((panel) => {
  pollRemediationJob(panel);
});

window.addEventListener('load', () => {
  const focusPanel = document.querySelector('[data-remediation-focus]');
  if (!focusPanel) return;
  focusPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
});
</script>"""


def render_findings_panel(
    findings_html: str,
) -> str:
    return f"""
    <section class="panel">
      <h2>Top Findings</h2>
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


def render_html_finding(
    finding: Finding,
    remediation_inputs: str = "",
    remediation_enabled: bool = False,
) -> str:
    evidence_items = "".join(
        f"<li><code>{html.escape(evidence.path)}{':' + str(evidence.line) if evidence.line else ''}</code> - {html.escape(evidence.snippet)}</li>"
        for evidence in finding.evidence
    )
    refs = ", ".join(finding.framework_refs)
    copy_text = html.escape(finding_copy_text(finding), quote=True)
    actions = render_finding_actions(finding, remediation_inputs, remediation_enabled)
    inline_console = render_inline_remediation_console()
    return f"""
<article class="card finding severity-{html.escape(finding.severity)}" data-finding-key="{html.escape(finding_key(finding), quote=True)}">
  <div class="finding-topline">
    <h3>[{html.escape(finding.severity.upper())}] {html.escape(finding.title)}</h3>
    <div class="action-cluster">
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
  {inline_console}
</article>
"""


def render_finding_actions(
    finding: Finding,
    remediation_inputs: str,
    remediation_enabled: bool,
) -> str:
    if not remediation_enabled:
        return "<span class='finding-note'>Codex actions are available when this repo was analyzed from a local path.</span>"

    hidden = remediation_inputs + (
        f"<input type='hidden' name='selected_finding' value='{html.escape(finding_key(finding), quote=True)}'>"
    )
    apply_form = (
        "<form class='action-form' method='post' action='/remediation-start-json' data-remediation-launch='true'>"
        f"{hidden}"
        "<input type='hidden' name='mode' value='apply'>"
        "<button class='action-button apply' type='submit' data-remediation-button='true' title='Fix with Codex'>Fix with Codex</button>"
        "</form>"
    )
    return apply_form


def render_inline_remediation_console() -> str:
    return """
  <section class="finding-console" data-inline-remediation hidden>
    <h4 class="console-title">Codex Output</h4>
    <div class="console-meta">
      <span class="status-pill" data-job-field="status">idle</span>
      <span><strong>Mode:</strong> <span data-job-field="mode">apply</span></span>
      <span><strong>Finding:</strong> <span data-job-field="finding_title"></span></span>
    </div>
    <p data-job-field="message">Waiting for Codex to start.</p>
    <pre class="console-log" data-job-field="logs"></pre>
  </section>
"""


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


def finding_key(finding: Finding) -> str:
    return f"{finding.rule_id}|{finding.title}"


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
