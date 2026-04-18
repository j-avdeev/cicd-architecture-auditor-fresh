from __future__ import annotations

import cgi
import html
import json
import shutil
import tempfile
import threading
import uuid
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urlparse

from auditor.config import app_env, gitlab_connection_from_env
from auditor.discovery import discover_ci_files
from auditor.gitlab_api import fetch_gitlab_recent_runs
from auditor.models import GitLabConnection, ProjectContext, RemediationResult, SavedContext
from auditor.remediation import execute_codex_for_findings, remediation_prompt, run_codex_for_finding, run_codex_for_findings
from auditor.report import base_script, base_styles, report_fragment
from auditor.rules import analyze


ROOT = Path(__file__).resolve().parent.parent
APP_VERSION = "build 2026-04-18d"
SAMPLES = {
    "GitHub Monorepo": ROOT / "samples" / "github_monorepo",
    "Legacy Jenkins": ROOT / "samples" / "jenkins_legacy",
    "Split GitLab + CircleCI": ROOT / "samples" / "split_estate",
}
JOBS: dict[str, dict[str, object]] = {}
JOB_LOCK = threading.Lock()


class AuditorHandler(BaseHTTPRequestHandler):
    server_version = "CICDAuditor/0.3"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        selected = params.get("sample", [""])[0]
        default_gitlab = gitlab_connection_from_env(app_env(ROOT))

        if parsed.path == "/job-status":
            self.handle_job_status(parsed)
            return

        if parsed.path == "/export-context":
            self.handle_export_context(parsed)
            return

        if parsed.path == "/":
            report_html = ""
            if selected in SAMPLES:
                report_html = self.render_report_for_target(
                    SAMPLES[selected],
                    f"Sample: {selected}",
                    context=ProjectContext(),
                    gitlab_connection=default_gitlab,
                )
            self.respond(self.page(report_html=report_html, selected_sample=selected, gitlab_connection=default_gitlab))
            return

        self.respond(self.page(error=f"Unknown path: {parsed.path}", gitlab_connection=default_gitlab), status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/remediation-review":
            self.handle_remediation_review()
            return
        if parsed.path == "/remediation-start":
            self.handle_remediation_start()
            return
        if parsed.path == "/remediate":
            self.handle_remediation()
            return
        if parsed.path == "/remediate-batch":
            self.handle_batch_remediation()
            return
        if parsed.path != "/analyze":
            self.respond(self.page(error=f"Unknown path: {parsed.path}"), status=HTTPStatus.NOT_FOUND)
            return

        content_type = self.headers.get_content_type()
        target_path = ""
        sample = ""
        upload = None
        context_upload = None
        context = ProjectContext()
        gitlab_connection = gitlab_connection_from_env(app_env(ROOT))

        if content_type == "application/x-www-form-urlencoded":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            params = parse_qs(raw)
            target_path = (params.get("target_path", [""])[0]).strip()
            sample = (params.get("sample", [""])[0]).strip()
            context = ProjectContext(
                description=(params.get("project_description", [""])[0]).strip(),
                stack=(params.get("project_stack", [""])[0]).strip(),
                goals=(params.get("project_goals", [""])[0]).strip(),
            )
            gitlab_connection = merge_gitlab_connection(
                gitlab_connection,
                base_url=(params.get("gitlab_base_url", [""])[0]).strip(),
                project=(params.get("gitlab_project", [""])[0]).strip(),
                ref=(params.get("gitlab_ref", [""])[0]).strip(),
            )
        else:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
                },
            )
            target_path = (form.getfirst("target_path") or "").strip()
            sample = (form.getfirst("sample") or "").strip()
            upload = form["repo_zip"] if "repo_zip" in form else None
            context_upload = form["context_file"] if "context_file" in form else None
            context = ProjectContext(
                description=(form.getfirst("project_description") or "").strip(),
                stack=(form.getfirst("project_stack") or "").strip(),
                goals=(form.getfirst("project_goals") or "").strip(),
            )
            gitlab_connection = merge_gitlab_connection(
                gitlab_connection,
                base_url=(form.getfirst("gitlab_base_url") or "").strip(),
                project=(form.getfirst("gitlab_project") or "").strip(),
                ref=(form.getfirst("gitlab_ref") or "").strip(),
            )

        try:
            if context_upload is not None and getattr(context_upload, "filename", ""):
                imported = parse_saved_context_upload(context_upload)
                target_path = imported.target_path or target_path
                context = imported.project_context
                gitlab_connection = merge_gitlab_connection(
                    gitlab_connection,
                    base_url=imported.gitlab_connection.base_url,
                    project=imported.gitlab_connection.project,
                    ref=imported.gitlab_connection.ref,
                )
                self.respond(
                    self.page(
                        target_path=target_path,
                        context=context,
                        gitlab_connection=gitlab_connection,
                    )
                )
                return

            if sample in SAMPLES:
                report_html = self.render_report_for_target(
                    SAMPLES[sample],
                    f"Sample: {sample}",
                    context=context,
                    gitlab_connection=gitlab_connection,
                )
                self.respond(
                    self.page(
                        report_html=report_html,
                        selected_sample=sample,
                        target_path=str(SAMPLES[sample]),
                        context=context,
                        gitlab_connection=gitlab_connection,
                    )
                )
                return

            if target_path:
                report_html = self.render_report_for_target(
                    Path(target_path).expanduser(),
                    target_path,
                    context=context,
                    gitlab_connection=gitlab_connection,
                )
                self.respond(
                    self.page(
                        report_html=report_html,
                        target_path=target_path,
                        context=context,
                        gitlab_connection=gitlab_connection,
                    )
                )
                return

            if upload is not None and getattr(upload, "filename", ""):
                report_html, display_path = self.render_report_for_upload(upload, context=context, gitlab_connection=gitlab_connection)
                self.respond(
                    self.page(
                        report_html=report_html,
                        upload_name=display_path,
                        context=context,
                        gitlab_connection=gitlab_connection,
                    )
                )
                return

            self.respond(
                self.page(
                    error="Provide a local path, choose a sample, upload a .zip file, or import a saved context.",
                    context=context,
                    gitlab_connection=gitlab_connection,
                ),
                status=HTTPStatus.BAD_REQUEST,
            )
        except Exception as exc:  # noqa: BLE001
            self.respond(
                self.page(
                    error=str(exc),
                    selected_sample=sample,
                    target_path=target_path,
                    context=context,
                    gitlab_connection=gitlab_connection,
                ),
                status=HTTPStatus.BAD_REQUEST,
            )

    def handle_job_status(self, parsed) -> None:
        job_id = (parse_qs(parsed.query).get("id", [""])[0]).strip()
        payload = job_payload(job_id)
        if payload is None:
            body = json.dumps({"error": f"Unknown remediation job: {job_id}"}).encode("utf-8")
            self.send_response(HTTPStatus.NOT_FOUND)
        else:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_remediation_review(self) -> None:
        default_gitlab = gitlab_connection_from_env(app_env(ROOT))
        params = read_urlencoded_params(self)
        target_path, selected_keys, mode, context = parse_remediation_params(params)

        try:
            target, files, analyzed = load_analysis_for_remediation(target_path, default_gitlab)
            selected_findings = resolve_selected_findings(analyzed, selected_keys)
            prompt_preview = remediation_prompt(selected_findings, target, context, mode)
            review_panel = render_remediation_review_panel(target, selected_findings, context, mode, prompt_preview)
            report_html = review_panel + report_fragment(
                analyzed,
                context=context,
                build_label=APP_VERSION,
                display_target=str(target),
                remediation_target=str(target),
            )
            self.respond(
                self.page(
                    report_html=report_html,
                    target_path=str(target),
                    context=context,
                    gitlab_connection=default_gitlab,
                )
            )
        except Exception as exc:  # noqa: BLE001
            remediation_result = RemediationResult(
                mode=mode,
                finding_title=f"{len(selected_keys)} findings" if selected_keys else "No findings selected",
                target_path=target_path,
                command="",
                success=False,
                message=str(exc),
                finding_count=len(selected_keys),
            )
            self.respond(
                self.page(
                    error=str(exc),
                    target_path=target_path,
                    context=context,
                    gitlab_connection=default_gitlab,
                    remediation_result=remediation_result,
                ),
                status=HTTPStatus.BAD_REQUEST,
            )

    def handle_remediation_start(self) -> None:
        default_gitlab = gitlab_connection_from_env(app_env(ROOT))
        params = read_urlencoded_params(self)
        target_path, selected_keys, mode, context = parse_remediation_params(params)

        try:
            target, files, analyzed = load_analysis_for_remediation(target_path, default_gitlab)
            selected_findings = resolve_selected_findings(analyzed, selected_keys)
            prompt_preview = remediation_prompt(selected_findings, target, context, mode)
            job_id = create_job(target, selected_findings, mode, prompt_preview)
            start_job_runner(job_id, target, selected_findings, context)
            console_panel = render_remediation_job_panel(job_id, target, selected_findings, context, mode, prompt_preview)
            report_html = console_panel + report_fragment(
                analyzed,
                context=context,
                build_label=APP_VERSION,
                display_target=str(target),
                remediation_target=str(target),
            )
            self.respond(
                self.page(
                    report_html=report_html,
                    target_path=str(target),
                    context=context,
                    gitlab_connection=default_gitlab,
                )
            )
        except Exception as exc:  # noqa: BLE001
            remediation_result = RemediationResult(
                mode=mode,
                finding_title=f"{len(selected_keys)} findings" if selected_keys else "No findings selected",
                target_path=target_path,
                command="",
                success=False,
                message=str(exc),
                finding_count=len(selected_keys),
            )
            self.respond(
                self.page(
                    error=str(exc),
                    target_path=target_path,
                    context=context,
                    gitlab_connection=default_gitlab,
                    remediation_result=remediation_result,
                ),
                status=HTTPStatus.BAD_REQUEST,
            )

    def handle_remediation(self) -> None:
        default_gitlab = gitlab_connection_from_env(app_env(ROOT))
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(raw)
        target_path = (params.get("target_path", [""])[0]).strip()
        rule_id = (params.get("rule_id", [""])[0]).strip()
        finding_title = (params.get("finding_title", [""])[0]).strip()
        mode = (params.get("mode", ["plan"])[0]).strip().lower() or "plan"
        context = ProjectContext(
            description=(params.get("project_description", [""])[0]).strip(),
            stack=(params.get("project_stack", [""])[0]).strip(),
            goals=(params.get("project_goals", [""])[0]).strip(),
        )

        try:
            if mode not in {"plan", "apply"}:
                raise ValueError(f"Unsupported remediation mode: {mode}")
            if not target_path:
                raise ValueError("Remediation requires a local repository path.")

            target = Path(target_path).expanduser().resolve()
            if not target.exists():
                raise ValueError(f"Target path does not exist: {target}")

            files = discover_ci_files(target)
            if not files:
                raise ValueError(f"No supported CI files found under: {target}")

            analyzed = analyze(target, files, recent_runs=fetch_recent_runs(default_gitlab))
            finding = next(
                (
                    item
                    for item in analyzed.findings
                    if item.rule_id == rule_id and item.title == finding_title
                ),
                None,
            )
            if finding is None:
                raise ValueError("That finding is no longer present. Please re-run the audit and try again.")

            remediation_result = run_codex_for_finding(target, finding, context, mode)
            refreshed = analyze(target, files, recent_runs=fetch_recent_runs(default_gitlab))
            self.respond(
                self.page(
                    report_html=report_fragment(
                        refreshed,
                        context=context,
                        build_label=APP_VERSION,
                        display_target=str(target),
                        remediation_target=str(target),
                        remediation_result=remediation_result,
                    ),
                    target_path=str(target),
                    context=context,
                    gitlab_connection=default_gitlab,
                )
            )
        except Exception as exc:  # noqa: BLE001
            remediation_result = RemediationResult(
                mode=mode,
                finding_title=finding_title or "Unknown finding",
                target_path=target_path,
                command="",
                success=False,
                message=str(exc),
            )
            self.respond(
                self.page(
                    error=str(exc),
                    target_path=target_path,
                    context=context,
                    gitlab_connection=default_gitlab,
                    remediation_result=remediation_result,
                ),
                status=HTTPStatus.BAD_REQUEST,
            )

    def handle_batch_remediation(self) -> None:
        default_gitlab = gitlab_connection_from_env(app_env(ROOT))
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(raw)
        target_path = (params.get("target_path", [""])[0]).strip()
        selected_keys = [item.strip() for item in params.get("selected_finding", []) if item.strip()]
        mode = (params.get("mode", ["plan"])[0]).strip().lower() or "plan"
        context = ProjectContext(
            description=(params.get("project_description", [""])[0]).strip(),
            stack=(params.get("project_stack", [""])[0]).strip(),
            goals=(params.get("project_goals", [""])[0]).strip(),
        )

        try:
            if mode not in {"plan", "apply"}:
                raise ValueError(f"Unsupported remediation mode: {mode}")
            if not target_path:
                raise ValueError("Batch remediation requires a local repository path.")
            if not selected_keys:
                raise ValueError("Select at least one finding before starting batch Codex remediation.")

            target = Path(target_path).expanduser().resolve()
            if not target.exists():
                raise ValueError(f"Target path does not exist: {target}")

            files = discover_ci_files(target)
            if not files:
                raise ValueError(f"No supported CI files found under: {target}")

            analyzed = analyze(target, files, recent_runs=fetch_recent_runs(default_gitlab))
            findings_by_key = {finding_lookup_key(item): item for item in analyzed.findings}
            selected_findings = [findings_by_key[key] for key in selected_keys if key in findings_by_key]
            if not selected_findings:
                raise ValueError("The selected findings are no longer present. Please re-run the audit and try again.")

            remediation_result = run_codex_for_findings(target, selected_findings, context, mode)
            refreshed = analyze(target, files, recent_runs=fetch_recent_runs(default_gitlab))
            self.respond(
                self.page(
                    report_html=report_fragment(
                        refreshed,
                        context=context,
                        build_label=APP_VERSION,
                        display_target=str(target),
                        remediation_target=str(target),
                        remediation_result=remediation_result,
                    ),
                    target_path=str(target),
                    context=context,
                    gitlab_connection=default_gitlab,
                )
            )
        except Exception as exc:  # noqa: BLE001
            remediation_result = RemediationResult(
                mode=mode,
                finding_title=f"{len(selected_keys)} findings" if selected_keys else "No findings selected",
                target_path=target_path,
                command="",
                success=False,
                message=str(exc),
                finding_count=len(selected_keys),
            )
            self.respond(
                self.page(
                    error=str(exc),
                    target_path=target_path,
                    context=context,
                    gitlab_connection=default_gitlab,
                    remediation_result=remediation_result,
                ),
                status=HTTPStatus.BAD_REQUEST,
            )

    def render_report_for_upload(
        self,
        upload: cgi.FieldStorage,
        context: ProjectContext,
        gitlab_connection: GitLabConnection,
    ) -> tuple[str, str]:
        filename = Path(upload.filename).name
        if not filename.lower().endswith(".zip"):
            raise ValueError("Uploaded file must be a .zip archive.")

        with tempfile.TemporaryDirectory(prefix="ci_auditor_upload_") as temp_dir:
            archive_path = Path(temp_dir) / filename
            with archive_path.open("wb") as handle:
                shutil.copyfileobj(upload.file, handle)

            extract_dir = Path(temp_dir) / "repo"
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(extract_dir)

            candidates = [extract_dir]
            children = [path for path in extract_dir.iterdir() if path.is_dir()]
            if len(children) == 1:
                candidates.insert(0, children[0])

            for candidate in candidates:
                files = discover_ci_files(candidate)
                if files:
                    result = analyze(candidate, files, recent_runs=fetch_recent_runs(gitlab_connection))
                    return (
                        report_fragment(
                            result,
                            context=context,
                            build_label=APP_VERSION,
                            display_target=filename,
                            remediation_target="",
                        ),
                        filename,
                    )

        raise ValueError("No supported CI files were found in the uploaded archive.")

    def render_report_for_target(
        self,
        target: Path,
        label: str,
        context: ProjectContext,
        gitlab_connection: GitLabConnection,
    ) -> str:
        resolved = target.resolve()
        if not resolved.exists():
            raise ValueError(f"Target path does not exist: {resolved}")

        files = discover_ci_files(resolved)
        if not files:
            raise ValueError(f"No supported CI files found under: {resolved}")

        result = analyze(resolved, files, recent_runs=fetch_recent_runs(gitlab_connection))
        return report_fragment(
            result,
            context=context,
            build_label=APP_VERSION,
            display_target=str(label),
            remediation_target=str(resolved),
        )

    def page(
        self,
        report_html: str = "",
        error: str = "",
        selected_sample: str = "",
        target_path: str = "",
        upload_name: str = "",
        context: ProjectContext | None = None,
        gitlab_connection: GitLabConnection | None = None,
        remediation_result: RemediationResult | None = None,
    ) -> str:
        context = context or ProjectContext()
        gitlab_connection = gitlab_connection or GitLabConnection()
        sample_cards = "".join(
            f"<button class='sample-card{' active' if name == selected_sample else ''}' type='submit' name='sample' value='{html.escape(name)}'>{html.escape(name)}</button>"
            for name in SAMPLES
        )
        report_section = ""
        if error:
            report_section = f"<section class='panel error'><h2>Analysis Error</h2><p>{html.escape(error)}</p></section>"
            if remediation_result is not None:
                report_section += remediation_error_panel(remediation_result)
        elif report_html:
            report_section = report_html

        upload_note = f"<p class='muted'>Last upload: {html.escape(upload_name)}</p>" if upload_name else ""
        export_href = (
            "/export-context?"
            + "&".join(
                [
                    f"target_path={quote_plus(target_path)}",
                    f"project_description={quote_plus(context.description)}",
                    f"project_stack={quote_plus(context.stack)}",
                    f"project_goals={quote_plus(context.goals)}",
                    f"gitlab_base_url={quote_plus(gitlab_connection.base_url)}",
                    f"gitlab_project={quote_plus(gitlab_connection.project)}",
                    f"gitlab_ref={quote_plus(gitlab_connection.ref)}",
                ]
            )
        )
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CI/CD Architecture Auditor</title>
  {base_styles()}
  <style>
    .app-shell {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 20px 56px;
    }}
    .intro {{
      display: grid;
      grid-template-columns: 1.25fr .9fr;
      gap: 18px;
      align-items: stretch;
    }}
    .eyebrow {{
      letter-spacing: .16em;
      text-transform: uppercase;
      font-size: 12px;
      color: var(--accent);
      margin-bottom: 14px;
    }}
    .headline {{
      font-size: clamp(2.2rem, 3.7vw, 4rem);
      line-height: .94;
      margin-bottom: 14px;
    }}
    .lead {{
      font-size: 1.05rem;
      color: var(--muted);
      max-width: 52ch;
    }}
    .control-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
      margin-top: 22px;
    }}
    .full-width {{
      margin-top: 18px;
    }}
    .form-stack {{
      display: grid;
      gap: 12px;
    }}
    label {{
      font-weight: bold;
      font-size: .95rem;
    }}
    input[type="text"], input[type="file"], textarea {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 14px;
      font: inherit;
      background: #fff;
    }}
    textarea {{
      min-height: 110px;
      resize: vertical;
    }}
    .build-callout {{
      display: inline-block;
      margin-top: 10px;
      color: var(--muted);
      font-size: .92rem;
    }}
    .button-row, .sample-grid {{
      display: grid;
      gap: 10px;
    }}
    .button-row {{
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    }}
    button {{
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      font: inherit;
      cursor: pointer;
      transition: transform .16s ease, box-shadow .16s ease, background .16s ease;
    }}
    .cta {{
      background: #0f766e;
      color: #fff;
      box-shadow: 0 10px 20px rgba(15,118,110,.18);
    }}
    .secondary {{
      background: #ece6da;
      color: var(--ink);
    }}
    .link-button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-decoration: none;
    }}
    button:hover, .link-button:hover {{
      transform: translateY(-1px);
    }}
    .sample-grid {{
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    }}
    .sample-card {{
      background: #fff;
      border: 1px solid var(--border);
      border-radius: 18px;
      text-align: left;
      padding: 16px;
    }}
    .sample-card.active {{
      outline: 2px solid rgba(15,118,110,.35);
      background: #f5fbfa;
    }}
    .facts {{
      display: grid;
      gap: 12px;
    }}
    .fact {{
      border-top: 1px solid var(--border);
      padding-top: 12px;
    }}
    .error {{
      border-color: #ef4444;
      background: #fff7f7;
    }}
    .warning-note {{
      border-color: #d97706;
      background: #fff8eb;
    }}
    .report-shell {{
      padding-left: 0;
      padding-right: 0;
    }}
    @media (max-width: 860px) {{
      .intro, .control-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="app-shell">
    <section class="hero intro">
      <div>
        <div class="eyebrow">Hackathon MVP</div>
        <h1 class="headline">Turn CI/CD drift into a migration plan with evidence.</h1>
        <p class="lead">Analyze a local repository or uploaded archive and get a scorecard across security, reliability, maintainability, scalability, and cost.</p>
        <p class="build-callout">Analyzer version: <strong>{html.escape(APP_VERSION)}</strong></p>
      </div>
      <div class="panel facts">
        <div class="fact">
          <strong>What it reads</strong>
          <p class="muted">GitHub Actions, GitLab CI, Jenkinsfiles, and CircleCI config.</p>
        </div>
        <div class="fact">
          <strong>What it outputs</strong>
          <p class="muted">Architectural findings, confidence hints, and a phased modernization roadmap.</p>
        </div>
        <div class="fact">
          <strong>Fastest demo path</strong>
          <p class="muted">Run one of the built-in scenarios below, then switch to a real repo path or zip upload.</p>
        </div>
      </div>
    </section>

    <section class="panel">
      <h2>Analyze</h2>
      <div class="control-grid">
        <form class="form-stack" method="post" action="/analyze">
          <label for="target_path">Local repository path</label>
          <input id="target_path" type="text" name="target_path" value="{html.escape(target_path)}" placeholder="C:\\repos\\my-service">
          <div class="button-row">
            <button class="cta" type="submit">Analyze Path</button>
            <a href="/" style="text-decoration:none;"><button class="secondary" type="button">Reset</button></a>
          </div>
        </form>

        <form class="form-stack" method="post" action="/analyze" enctype="multipart/form-data">
          <label for="repo_zip">Upload zipped repo</label>
          <input id="repo_zip" type="file" name="repo_zip" accept=".zip">
          <label for="context_file">Import saved context</label>
          <input id="context_file" type="file" name="context_file" accept=".json">
          <div class="button-row">
            <button class="cta" type="submit">Analyze Zip / Import</button>
            <a class="secondary link-button" href="{html.escape(export_href)}">Export Context</a>
          </div>
          {upload_note}
        </form>
      </div>
      <form class="form-stack full-width" method="post" action="/analyze">
        <input type="hidden" name="target_path" value="{html.escape(target_path)}">
        <label for="project_description">What is this project?</label>
        <textarea id="project_description" name="project_description" placeholder="Desktop simulation product, legacy Windows app, internal tooling, monorepo, etc.">{html.escape(context.description)}</textarea>
        <label for="project_stack">Stack / delivery stack</label>
        <textarea id="project_stack" name="project_stack" placeholder="GitLab CI, Nexus, Windows runners, PowerShell, Python, Qt, Jenkins, Docker, Kubernetes, etc.">{html.escape(context.stack)}</textarea>
        <label for="project_goals">What do you want from the auditor?</label>
        <textarea id="project_goals" name="project_goals" placeholder="Harden GitLab pipeline, remove brittle runner paths, prepare migration to Jenkins/GitHub Actions, improve Nexus publishing, reduce manual steps, etc.">{html.escape(context.goals)}</textarea>
        <div class="button-row">
          <button class="cta" type="submit">Analyze With Context</button>
        </div>
        <label for="gitlab_base_url">GitLab base URL for recent runs</label>
        <input id="gitlab_base_url" type="text" name="gitlab_base_url" value="{html.escape(gitlab_connection.base_url)}" placeholder="https://gitlab.example.com">
        <label for="gitlab_project">GitLab project path or ID</label>
        <input id="gitlab_project" type="text" name="gitlab_project" value="{html.escape(gitlab_connection.project)}" placeholder="group/project or numeric project id">
        <label for="gitlab_ref">GitLab ref</label>
        <input id="gitlab_ref" type="text" name="gitlab_ref" value="{html.escape(gitlab_connection.ref)}" placeholder="main or release branch (optional)">
      </form>
    </section>

    <section class="panel">
      <h2>Demo Scenarios</h2>
      <form method="post" action="/analyze">
        <div class="sample-grid">
          {sample_cards}
        </div>
      </form>
    </section>

    <section class="panel warning-note">
      <h2>MVP Guardrail</h2>
      <p>A score of 100/100 with 0 findings means only that the current rule set did not match anything in the detected CI files. It is not a proof that the pipeline is clean.</p>
      <p>If you do not see the analyzer version badge or the Discovery Debug section in the report, you are looking at an older server process and should restart the app.</p>
      <p>Recent GitLab run enrichment is available when `GITLAB_BASE_URL`, `GITLAB_PROJECT`, and `GITLAB_TOKEN` are set in `.env`, optionally with `GITLAB_REF`.</p>
      <p>You can now export/import saved context as JSON so repo path and project notes do not need to be typed every time.</p>
    </section>

    {report_section}
  </main>
</body>
{base_script()}
</html>
"""

    def respond(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def handle_export_context(self, parsed) -> None:
        params = parse_qs(parsed.query)
        saved = SavedContext(
            target_path=(params.get("target_path", [""])[0]).strip(),
            project_context=ProjectContext(
                description=(params.get("project_description", [""])[0]).strip(),
                stack=(params.get("project_stack", [""])[0]).strip(),
                goals=(params.get("project_goals", [""])[0]).strip(),
            ),
            gitlab_connection=GitLabConnection(
                base_url=(params.get("gitlab_base_url", [""])[0]).strip(),
                project=(params.get("gitlab_project", [""])[0]).strip(),
                ref=(params.get("gitlab_ref", [""])[0]).strip(),
                pipeline_limit=5,
            ),
        )
        payload = json.dumps(saved.as_dict(), indent=2).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="auditor-context.json"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), AuditorHandler)
    print(f"Serving CI/CD Architecture Auditor {APP_VERSION} on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def read_urlencoded_params(handler: AuditorHandler) -> dict[str, list[str]]:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length).decode("utf-8", errors="replace")
    return parse_qs(raw)


def parse_remediation_params(params: dict[str, list[str]]) -> tuple[str, list[str], str, ProjectContext]:
    target_path = (params.get("target_path", [""])[0]).strip()
    selected_keys = [item.strip() for item in params.get("selected_finding", []) if item.strip()]
    mode = (params.get("mode", ["plan"])[0]).strip().lower() or "plan"
    context = ProjectContext(
        description=(params.get("project_description", [""])[0]).strip(),
        stack=(params.get("project_stack", [""])[0]).strip(),
        goals=(params.get("project_goals", [""])[0]).strip(),
    )
    return target_path, selected_keys, mode, context


def load_analysis_for_remediation(target_path: str, gitlab_connection: GitLabConnection) -> tuple[Path, list, object]:
    if not target_path:
        raise ValueError("Remediation requires a local repository path.")

    target = Path(target_path).expanduser().resolve()
    if not target.exists():
        raise ValueError(f"Target path does not exist: {target}")

    files = discover_ci_files(target)
    if not files:
        raise ValueError(f"No supported CI files found under: {target}")

    analyzed = analyze(target, files, recent_runs=fetch_recent_runs(gitlab_connection))
    return target, files, analyzed


def resolve_selected_findings(analyzed, selected_keys: list[str]):
    if not selected_keys:
        raise ValueError("Select at least one finding before starting Codex remediation.")
    findings_by_key = {finding_lookup_key(item): item for item in analyzed.findings}
    selected_findings = [findings_by_key[key] for key in selected_keys if key in findings_by_key]
    if not selected_findings:
        raise ValueError("The selected findings are no longer present. Please re-run the audit and try again.")
    return selected_findings


def create_job(target: Path, findings, mode: str, prompt_preview: str) -> str:
    job_id = uuid.uuid4().hex[:10]
    title = findings[0].title if len(findings) == 1 else f"{len(findings)} findings"
    with JOB_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "mode": mode,
            "target_path": str(target),
            "finding_title": title,
            "finding_count": len(findings),
            "prompt_preview": prompt_preview,
            "logs": "[auditor] Job queued.\n",
            "last_message": "",
            "message": "Waiting for Codex to start.",
            "success": None,
            "command": "",
        }
    return job_id


def append_job_log(job_id: str, message: str) -> None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        current = str(job.get("logs", ""))
        line = message.rstrip()
        if not line:
            return
        job["logs"] = (current + line + "\n")[-20000:]


def update_job(job_id: str, **values) -> None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        job.update(values)


def job_payload(job_id: str) -> dict[str, object] | None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return None
        return dict(job)


def start_job_runner(job_id: str, target: Path, findings, context: ProjectContext) -> None:
    def runner() -> None:
        job = job_payload(job_id)
        if job is None:
            return
        mode = str(job["mode"])
        update_job(job_id, status="running", message="Codex is running.")
        append_job_log(job_id, "[auditor] Job started.")
        try:
            result = execute_codex_for_findings(
                target,
                findings,
                context,
                mode,
                on_log=lambda line: append_job_log(job_id, line),
            )
            update_job(
                job_id,
                status="completed" if result.success else "failed",
                message=result.message,
                success=result.success,
                last_message=result.last_message,
                command=result.command,
            )
        except Exception as exc:  # noqa: BLE001
            append_job_log(job_id, f"[auditor] {exc}")
            update_job(
                job_id,
                status="failed",
                message=str(exc),
                success=False,
            )

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()


def remediation_hidden_inputs_for_page(target: Path, findings, context: ProjectContext, mode: str) -> str:
    values = [
        ("target_path", str(target)),
        ("mode", mode),
        ("project_description", context.description),
        ("project_stack", context.stack),
        ("project_goals", context.goals),
    ]
    inputs = [
        f"<input type='hidden' name='{html.escape(name)}' value='{html.escape(value, quote=True)}'>"
        for name, value in values
    ]
    inputs.extend(
        f"<input type='hidden' name='selected_finding' value='{html.escape(finding_lookup_key(finding), quote=True)}'>"
        for finding in findings
    )
    return "".join(inputs)


def render_remediation_review_panel(target: Path, findings, context: ProjectContext, mode: str, prompt_preview: str) -> str:
    button_label = "Approve and start Fix with Codex" if mode == "apply" else "Start Plan with Codex"
    note = (
        "<p class='approval-note'>Approval required before Codex is allowed to modify files in this repository.</p>"
        if mode == "apply"
        else "<p class='muted'>This run is read-only and will ask Codex for a remediation plan.</p>"
    )
    hidden = remediation_hidden_inputs_for_page(target, findings, context, mode)
    return f"""
    <section class="panel review-panel">
      <h2>Remediation Review</h2>
      <p><strong>Mode:</strong> {html.escape(mode)} | <strong>Repo:</strong> {html.escape(str(target))}</p>
      <p><strong>Selected findings:</strong> {len(findings)}</p>
      {note}
      <div class="console-meta">
        <form method="post" action="/remediation-start">
          {hidden}
          <button class="action-button{' apply' if mode == 'apply' else ''}" type="submit">{html.escape(button_label)}</button>
        </form>
      </div>
      <h3>Prompt Preview</h3>
      <pre>{html.escape(prompt_preview)}</pre>
    </section>
"""


def render_remediation_job_panel(job_id: str, target: Path, findings, context: ProjectContext, mode: str, prompt_preview: str) -> str:
    reanalyze_inputs = "".join(
        [
            f"<input type='hidden' name='target_path' value='{html.escape(str(target), quote=True)}'>",
            f"<input type='hidden' name='project_description' value='{html.escape(context.description, quote=True)}'>",
            f"<input type='hidden' name='project_stack' value='{html.escape(context.stack, quote=True)}'>",
            f"<input type='hidden' name='project_goals' value='{html.escape(context.goals, quote=True)}'>",
        ]
    )
    title = findings[0].title if len(findings) == 1 else f"{len(findings)} findings"
    return f"""
    <section class="panel console-panel" data-remediation-job="{html.escape(job_id)}">
      <h2>Job Console</h2>
      <div class="console-meta">
        <span class="status-pill" data-job-field="status">queued</span>
        <span><strong>Mode:</strong> {html.escape(mode)}</span>
        <span><strong>Target:</strong> {html.escape(title)}</span>
        <span><strong>Repo:</strong> {html.escape(str(target))}</span>
      </div>
      <p data-job-field="message">Waiting for Codex to start.</p>
      <p class="muted"><strong>Last Codex summary:</strong> <span data-job-field="last_message"></span></p>
      <div class="console-meta">
        <form method="post" action="/analyze">
          {reanalyze_inputs}
          <button class="action-button" type="submit">Re-audit this repo</button>
        </form>
      </div>
      <h3>Prompt Preview</h3>
      <pre>{html.escape(prompt_preview)}</pre>
      <h3>Console Output</h3>
      <pre data-job-field="logs">[auditor] Job queued.</pre>
    </section>
"""


def merge_gitlab_connection(connection: GitLabConnection, base_url: str = "", project: str = "", ref: str = "") -> GitLabConnection:
    return GitLabConnection(
        base_url=base_url or connection.base_url,
        project=project or connection.project,
        token=connection.token,
        ref=ref or connection.ref,
        pipeline_limit=connection.pipeline_limit,
    )


def fetch_recent_runs(connection: GitLabConnection):
    if not connection.enabled:
        return None
    try:
        return fetch_gitlab_recent_runs(connection)
    except Exception:  # noqa: BLE001
        return None


def parse_saved_context_upload(upload: cgi.FieldStorage) -> SavedContext:
    filename = Path(upload.filename).name
    if not filename.lower().endswith(".json"):
        raise ValueError("Context import file must be a JSON file.")

    payload = json.loads(upload.file.read().decode("utf-8-sig"))
    project_context_data = payload.get("project_context", {})
    gitlab_data = payload.get("gitlab", {})
    return SavedContext(
        target_path=str(payload.get("target_path", "")),
        project_context=ProjectContext(
            description=str(project_context_data.get("description", "")),
            stack=str(project_context_data.get("stack", "")),
            goals=str(project_context_data.get("goals", "")),
        ),
        gitlab_connection=GitLabConnection(
            base_url=str(gitlab_data.get("base_url", "")),
            project=str(gitlab_data.get("project", "")),
            ref=str(gitlab_data.get("ref", "")),
            pipeline_limit=int(gitlab_data.get("pipeline_limit", 5) or 5),
        ),
    )


def finding_lookup_key(finding) -> str:
    return f"{finding.rule_id}|{finding.title}"


def remediation_error_panel(remediation_result: RemediationResult) -> str:
    summary = html.escape(remediation_result.last_message or remediation_result.message)
    output = (
        f"<pre>{html.escape(remediation_result.raw_output)}</pre>"
        if remediation_result.raw_output
        else ""
    )
    return f"""
    <section class="panel">
      <h2>Codex Remediation</h2>
      <p><strong>Mode:</strong> {html.escape(remediation_result.mode)} | <strong>Finding:</strong> {html.escape(remediation_result.finding_title)}</p>
      <p><strong>Repo:</strong> {html.escape(remediation_result.target_path)}</p>
      <p>{summary}</p>
      {output}
    </section>
"""
