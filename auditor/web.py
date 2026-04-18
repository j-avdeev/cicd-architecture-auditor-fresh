from __future__ import annotations

import cgi
import html
import json
import os
import shutil
import subprocess
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
APP_VERSION = "build 2026-04-18f"
HISTORY_PATH = ROOT / ".auditor-history.json"
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
        if parsed.path == "/job-stop":
            self.handle_job_stop()
            return
        if parsed.path == "/remediation-review":
            self.handle_remediation_review()
            return
        if parsed.path == "/remediation-start":
            self.handle_remediation_start()
            return
        if parsed.path == "/job-finalize":
            self.handle_job_finalize()
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

    def handle_job_stop(self) -> None:
        params = read_urlencoded_params(self)
        job_id = (params.get("job_id", [""])[0]).strip()
        try:
            result = stop_job(job_id)
            body = json.dumps({"ok": True, **result}).encode("utf-8")
            self.send_response(HTTPStatus.OK)
        except Exception as exc:  # noqa: BLE001
            body = json.dumps({"ok": False, "error": str(exc)}).encode("utf-8")
            self.send_response(HTTPStatus.BAD_REQUEST)
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
            job_id = create_job(target, selected_findings, mode, prompt_preview, context)
            start_job_runner(job_id, target, selected_findings, context)
            console_panel = render_remediation_job_panel(job_id, target, selected_findings, context, mode, prompt_preview)
            inline_job_key = finding_lookup_key(selected_findings[0]) if len(selected_findings) == 1 else ""
            inline_console_panel = (
                render_remediation_job_panel(job_id, target, selected_findings, context, mode, prompt_preview, compact=True)
                if inline_job_key
                else ""
            )
            report_html = console_panel + report_fragment(
                analyzed,
                context=context,
                build_label=APP_VERSION,
                display_target=str(target),
                remediation_target=str(target),
                inline_job_key=inline_job_key,
                inline_job_html=inline_console_panel,
                active_job_id=job_id,
                active_job_key=inline_job_key,
                active_job_status="running",
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

    def handle_job_finalize(self) -> None:
        default_gitlab = gitlab_connection_from_env(app_env(ROOT))
        params = read_urlencoded_params(self)
        job_id = (params.get("job_id", [""])[0]).strip()
        action = (params.get("action", ["keep"])[0]).strip().lower() or "keep"

        try:
            job = job_payload(job_id)
            if job is None:
                raise ValueError(f"Unknown remediation job: {job_id}")
            if action not in {"keep", "revert"}:
                raise ValueError(f"Unsupported finalize action: {action}")

            target = Path(str(job["target_path"])).expanduser().resolve()
            context = ProjectContext(
                description=str(job.get("project_description", "")),
                stack=str(job.get("project_stack", "")),
                goals=str(job.get("project_goals", "")),
            )

            if action == "revert":
                outcome = revert_job_changes(job_id)
                append_job_event(job_id, "Changes reverted", outcome)
                append_repo_history(target, {"label": "Changes reverted", "detail": outcome, "status": "reverted"})
            else:
                outcome = "Codex changes were kept and the repo was re-audited."
                append_job_event(job_id, "Changes accepted", outcome)
                append_repo_history(target, {"label": "Changes accepted", "detail": outcome, "status": "accepted"})

            files = discover_ci_files(target)
            result = analyze(target, files, recent_runs=fetch_recent_runs(default_gitlab))
            refresh_saved_repo_history(job_id)
            remediation_result = RemediationResult(
                mode=str(job.get("mode", "apply")),
                finding_title=str(job.get("finding_title", "")),
                target_path=str(target),
                command=str(job.get("command", "")),
                success=True,
                message=outcome,
                finding_count=int(job.get("finding_count", 1) or 1),
                last_message=str(job.get("last_message", "")),
                raw_output=str(job.get("logs", ""))[-12000:],
            )
            self.respond(
                self.page(
                    report_html=report_fragment(
                        result,
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
            self.respond(
                self.page(
                    error=str(exc),
                    gitlab_connection=default_gitlab,
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

    <section class="panel">
      <p id="remediation-inline-status" class="inline-status"></p>
      <details class="panel debug-panel">
        <summary>Remediation Debug Log</summary>
        <pre id="remediation-debug-log" class="debug-log">Waiting for remediation activity...</pre>
      </details>
      <div id="dynamic-report-root">
        {report_section}
      </div>
    </section>
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


def create_job(target: Path, findings, mode: str, prompt_preview: str, context: ProjectContext) -> str:
    job_id = uuid.uuid4().hex[:10]
    title = findings[0].title if len(findings) == 1 else f"{len(findings)} findings"
    baseline = capture_git_state(target)
    file_severity_map = build_file_severity_map(findings)
    inline_job_key = finding_lookup_key(findings[0]) if len(findings) == 1 else ""
    events = [
        {
            "label": "Job created",
            "detail": f"{mode.title()} run prepared for {len(findings)} finding(s).",
        }
    ]
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
            "process_id": None,
            "stop_requested": False,
            "changed_files": "",
            "diff_stat": "",
            "diff_text": "",
            "changed_files_html": "<p class='muted'>Waiting for job completion...</p>",
            "diff_sections_html": "<p class='muted'>Waiting for job completion...</p>",
            "history_html": format_history_html(events),
            "repo_history_html": render_saved_repo_history_html(target),
            "inline_job_key": inline_job_key,
            "git_available": baseline["git_available"],
            "baseline_clean": baseline["clean"],
            "review_message": baseline["review_message"],
            "baseline_status": baseline["status_map"],
            "file_severity_map": file_severity_map,
            "project_description": context.description,
            "project_stack": context.stack,
            "project_goals": context.goals,
            "events": events,
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


def append_job_event(job_id: str, label: str, detail: str) -> None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        events = list(job.get("events", []))
        events.append({"label": label, "detail": detail})
        job["events"] = events[-12:]
        job["history_html"] = format_history_html(job["events"])


def refresh_saved_repo_history(job_id: str) -> None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        job["repo_history_html"] = render_saved_repo_history_html(Path(str(job["target_path"])))


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


def stop_job(job_id: str) -> dict[str, object]:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            raise ValueError(f"Unknown remediation job: {job_id}")
        status = str(job.get("status", ""))
        if status not in {"queued", "running", "stopping"}:
            raise ValueError(f"Job {job_id} is not running.")
        pid = job.get("process_id")
        job["stop_requested"] = True
        if status == "queued":
            job["status"] = "stopped"
            job["message"] = "Codex run was stopped before it started."
            job["success"] = False
            job["process_id"] = None
        else:
            job["status"] = "stopping"
            job["message"] = "Stopping Codex run..."

    append_job_log(job_id, "[auditor] Stop requested by user.")
    append_job_event(job_id, "Stop requested", "The user asked the app to terminate this Codex run.")

    if status == "queued":
        target = Path(str(job["target_path"]))
        append_repo_history(
            target,
            {
                "label": "Run stopped",
                "detail": "The run was stopped before Codex started.",
                "status": "reverted",
            },
        )
        refresh_saved_repo_history(job_id)
        return {"job_id": job_id, "status": "stopped", "message": "Codex run was stopped before it started."}

    if not pid:
        return {"job_id": job_id, "status": "stopping", "message": "Stopping Codex run..."}

    completed = subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    output = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode == 0:
        append_job_log(job_id, f"[auditor] taskkill succeeded for PID {pid}.")
        if output:
            append_job_log(job_id, output)
    else:
        append_job_log(job_id, f"[auditor] taskkill returned {completed.returncode} for PID {pid}.")
        if output:
            append_job_log(job_id, output)
    return {"job_id": job_id, "status": "stopping", "message": "Stopping Codex run..."}


def start_job_runner(job_id: str, target: Path, findings, context: ProjectContext) -> None:
    def runner() -> None:
        job = job_payload(job_id)
        if job is None:
            return
        mode = str(job["mode"])
        update_job(job_id, status="running", message="Codex is running.")
        append_job_log(job_id, "[auditor] Job started.")
        append_job_event(job_id, "Codex started", "The remediation runner launched and is streaming output.")
        append_repo_history(
            target,
            {
                "label": "Run started",
                "detail": f"{mode.title()} run for {len(findings)} finding(s).",
                "status": "running",
            },
        )
        refresh_saved_repo_history(job_id)
        try:
            result = execute_codex_for_findings(
                target,
                findings,
                context,
                mode,
                on_log=lambda line: append_job_log(job_id, line),
                on_process_start=lambda pid: update_job(job_id, process_id=pid),
            )
            latest = job_payload(job_id) or {}
            was_stopped = bool(latest.get("stop_requested")) or str(latest.get("status", "")) in {"stopping", "stopped"}
            final_status = "stopped" if was_stopped else ("completed" if result.success else "failed")
            final_message = "Codex run was stopped by the user." if was_stopped else result.message
            update_job(
                job_id,
                status=final_status,
                message=final_message,
                success=False if was_stopped else result.success,
                last_message=result.last_message,
                command=result.command,
                process_id=None,
            )
            update_job(job_id, **capture_review_artifacts(job_id, target))
            append_job_event(
                job_id,
                "Codex stopped" if was_stopped else ("Codex finished" if result.success else "Codex failed"),
                final_message,
            )
            append_repo_history(
                target,
                {
                    "label": "Run stopped" if was_stopped else ("Run completed" if result.success else "Run failed"),
                    "detail": final_message,
                    "status": "reverted" if was_stopped else ("completed" if result.success else "failed"),
                },
            )
            refresh_saved_repo_history(job_id)
        except Exception as exc:  # noqa: BLE001
            append_job_log(job_id, f"[auditor] {exc}")
            append_job_event(job_id, "Runner error", str(exc))
            append_repo_history(
                target,
                {
                    "label": "Runner error",
                    "detail": str(exc),
                    "status": "failed",
                },
            )
            refresh_saved_repo_history(job_id)
            update_job(
                job_id,
                status="failed",
                message=str(exc),
                success=False,
                process_id=None,
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
    <section class="panel review-panel" id="remediation-review-panel" data-remediation-review="true">
      <h2>Remediation Review</h2>
      <p><strong>Mode:</strong> {html.escape(mode)} | <strong>Repo:</strong> {html.escape(str(target))}</p>
      <p><strong>Selected findings:</strong> {len(findings)}</p>
      {note}
      <p><strong>Next step:</strong> Review the prompt below, then click <code>{html.escape(button_label)}</code> to open the live Codex job console.</p>
      <div class="console-meta">
        <form method="post" action="/remediation-start" data-remediation-async="true">
          {hidden}
          <button class="action-button{' apply' if mode == 'apply' else ''}" type="submit">{html.escape(button_label)}</button>
        </form>
      </div>
      <h3>Prompt Preview</h3>
      <pre>{html.escape(prompt_preview)}</pre>
    </section>
"""


def render_remediation_job_panel(job_id: str, target: Path, findings, context: ProjectContext, mode: str, prompt_preview: str, compact: bool = False) -> str:
    reanalyze_inputs = "".join(
        [
            f"<input type='hidden' name='target_path' value='{html.escape(str(target), quote=True)}'>",
            f"<input type='hidden' name='project_description' value='{html.escape(context.description, quote=True)}'>",
            f"<input type='hidden' name='project_stack' value='{html.escape(context.stack, quote=True)}'>",
            f"<input type='hidden' name='project_goals' value='{html.escape(context.goals, quote=True)}'>",
        ]
    )
    title = findings[0].title if len(findings) == 1 else f"{len(findings)} findings"
    action_inputs = (
        f"<input type='hidden' name='job_id' value='{html.escape(job_id, quote=True)}'>"
    )
    if compact:
        return f"""
    <section class="panel console-panel" data-remediation-job="{html.escape(job_id)}">
      <h3>Console Output</h3>
      <div class="console-meta">
        <span class="status-pill" data-job-field="status">queued</span>
        <span><strong>Mode:</strong> {html.escape(mode)}</span>
      </div>
      <p data-job-field="message">Waiting for Codex to start.</p>
      <p><strong>Console Output</strong></p>
      <pre class="console-log" data-job-field="logs">[auditor] Job queued.</pre>
    </section>
"""
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
      <h3>Review</h3>
      <p data-job-field="review_message">Review data will appear after the job finishes.</p>
      <p class="finalize-note">`Accept and Re-audit` keeps the Codex changes and refreshes the scorecard. `Revert and Re-audit` is available only when the target repo started clean.</p>
      <p><strong>Timeline</strong></p>
      <div data-job-html="history_html"><p class='muted'>Timeline will appear as the job progresses.</p></div>
      <p><strong>Saved repo history</strong></p>
      <div data-job-html="repo_history_html"><p class='muted'>Saved remediation history will appear here.</p></div>
      <p><strong>Changed files</strong></p>
      <div data-job-html="changed_files_html"><p class='muted'>Waiting for job completion...</p></div>
      <p><strong>Diff stat</strong></p>
      <pre data-job-field="diff_stat">Waiting for job completion...</pre>
      <p><strong>Diff by file</strong></p>
      <div class="console-meta">
        <button class="action-button" type="button" data-toggle-diffs="open">Expand all diffs</button>
        <button class="action-button" type="button" data-toggle-diffs="close">Collapse all diffs</button>
      </div>
      <div data-job-html="diff_sections_html"><p class='muted'>Waiting for job completion...</p></div>
      <div class="console-meta">
        <form method="post" action="/job-finalize" data-remediation-async="true">
          {action_inputs}
          <input type="hidden" name="action" value="keep">
          <button class="action-button apply" type="submit">Accept and Re-audit</button>
        </form>
        <form method="post" action="/job-finalize" data-remediation-async="true">
          {action_inputs}
          <input type="hidden" name="action" value="revert">
          <button class="action-button" type="submit">Revert and Re-audit</button>
        </form>
      </div>
      <h3>Prompt Preview</h3>
      <pre>{html.escape(prompt_preview)}</pre>
      <h3>Console Output</h3>
      <pre class="console-log" data-job-field="logs">[auditor] Job queued.</pre>
    </section>
"""


def run_git(target: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(target), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


def capture_git_state(target: Path) -> dict[str, object]:
    probe = run_git(target, "rev-parse", "--is-inside-work-tree")
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return {
            "git_available": False,
            "clean": False,
            "status_map": {},
            "review_message": "Diff review and revert are available only for git-backed repos.",
        }

    status = run_git(target, "status", "--porcelain")
    status_map = parse_status_map(status.stdout)
    return {
        "git_available": True,
        "clean": len(status_map) == 0,
        "status_map": status_map,
        "review_message": (
            "Repo started clean, so revert can restore Codex changes safely."
            if len(status_map) == 0
            else "Repo was already dirty before the run, so automatic revert is disabled to avoid touching unrelated work."
        ),
    }


def parse_status_map(status_output: str) -> dict[str, str]:
    status_map: dict[str, str] = {}
    for raw_line in status_output.splitlines():
        if len(raw_line) < 4:
            continue
        code = raw_line[:2]
        path = raw_line[3:]
        status_map[path] = code
    return status_map


def capture_review_artifacts(job_id: str, target: Path) -> dict[str, object]:
    job = job_payload(job_id) or {}
    git_available = bool(job.get("git_available"))
    baseline_clean = bool(job.get("baseline_clean"))
    if not git_available:
        return {
            "changed_files": "Not available for non-git targets.",
            "diff_stat": "Not available for non-git targets.",
            "diff_text": "Not available for non-git targets.",
            "changed_files_html": "<p class='muted'>Not available for non-git targets.</p>",
            "diff_sections_html": "<p class='muted'>Not available for non-git targets.</p>",
        }

    status = run_git(target, "status", "--short")
    diff_stat = run_git(target, "diff", "--stat")
    diff_text = run_git(target, "diff", "--no-ext-diff", "--unified=3")
    current_status = status.stdout.strip() or "No working tree changes."
    stat_text = diff_stat.stdout.strip() or "No diff stat available."
    diff_preview = diff_text.stdout.strip() or "No diff preview available."
    review_message = (
        "Review the changes below. You can accept them and re-audit, or revert them and re-audit."
        if baseline_clean
        else "Review is available, but automatic revert is disabled because the repo was already dirty before Codex ran."
    )
    return {
        "changed_files": current_status,
        "diff_stat": stat_text,
        "diff_text": diff_preview[-16000:],
        "changed_files_html": format_changed_files_html(status.stdout, dict(job.get("file_severity_map") or {})),
        "diff_sections_html": format_diff_sections_html(diff_text.stdout),
        "review_message": review_message,
        "current_status_map": parse_status_map(status.stdout),
    }


def revert_job_changes(job_id: str) -> str:
    job = job_payload(job_id)
    if job is None:
        raise ValueError(f"Unknown remediation job: {job_id}")
    if not job.get("git_available"):
        raise ValueError("Automatic revert is available only for git-backed repos.")
    if not job.get("baseline_clean"):
        raise ValueError("Automatic revert is disabled because the repo was already dirty before the Codex run.")

    target = Path(str(job["target_path"]))
    current_status_map = dict(job.get("current_status_map") or {})
    tracked_paths = [path for path, code in current_status_map.items() if code != "??"]
    untracked_paths = [path for path, code in current_status_map.items() if code == "??"]

    if tracked_paths:
        restore = run_git(target, "restore", "--staged", "--worktree", "--", *tracked_paths)
        if restore.returncode != 0:
            raise RuntimeError(restore.stderr.strip() or "git restore failed")

    for relative in untracked_paths:
        absolute = (target / relative).resolve()
        try:
            absolute.relative_to(target.resolve())
        except ValueError as exc:  # noqa: PERF203
            raise RuntimeError(f"Refusing to delete path outside target repo: {absolute}") from exc
        if absolute.is_dir():
            shutil.rmtree(absolute, ignore_errors=False)
        elif absolute.exists():
            absolute.unlink()

    return "Codex changes were reverted and the repo was re-audited."


def format_changed_files_html(status_output: str, file_severity_map: dict[str, str]) -> str:
    entries = []
    for raw_line in status_output.splitlines():
        if len(raw_line) < 4:
            continue
        code = raw_line[:2]
        path = raw_line[3:]
        normalized = path.replace("\\", "/")
        severity = file_severity_map.get(normalized) or file_severity_map.get(path) or "info"
        entries.append(
            "<div class='card review-card'>"
            f"<p><strong>{html.escape(path)}</strong></p>"
            f"<p><span class='severity-badge severity-{html.escape(severity)}'>{html.escape(severity.title())}</span></p>"
            f"<p class='muted'>Git status: {html.escape(code)}</p>"
            "</div>"
        )
    if not entries:
        return "<p class='muted'>No working tree changes detected.</p>"
    return "<div class='grid'>" + "".join(entries) + "</div>"


def format_diff_sections_html(diff_output: str) -> str:
    sections: list[str] = []
    chunks = diff_output.split("diff --git ")
    for chunk in chunks:
        if not chunk.strip():
            continue
        body = ("diff --git " + chunk).strip()
        lines = body.splitlines()
        header = lines[0] if lines else "diff"
        title = header.replace("diff --git a/", "").replace(" b/", " -> ")
        preview = "\n".join(lines[:80])
        sections.append(
            "<details class='card review-card diff-card'>"
            f"<summary>{html.escape(title)}</summary>"
            f"<pre>{html.escape(preview)}</pre>"
            "</details>"
        )
    if not sections:
        return "<p class='muted'>No diff sections available.</p>"
    return "".join(sections)


def format_history_html(events: list[dict[str, str]]) -> str:
    if not events:
        return "<p class='muted'>No remediation history yet.</p>"
    items = []
    for event in events[-8:]:
        items.append(
            "<div class='card history-card'>"
            f"<p><strong>{html.escape(event['label'])}</strong></p>"
            f"<p class='muted'>{html.escape(event['detail'])}</p>"
            "</div>"
        )
    return "<div class='grid'>" + "".join(items) + "</div>"


def build_file_severity_map(findings) -> dict[str, str]:
    ranking = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    mapping: dict[str, str] = {}
    for finding in findings:
        severity = getattr(finding, "severity", "info")
        for evidence in getattr(finding, "evidence", []) or []:
            path = str(getattr(evidence, "path", "")).replace("\\", "/")
            if not path:
                continue
            current = mapping.get(path, "info")
            if ranking.get(severity, 0) >= ranking.get(current, 0):
                mapping[path] = severity
    return mapping


def history_repo_key(target: Path) -> str:
    return str(target.resolve()).lower()


def load_saved_history() -> dict[str, list[dict[str, str]]]:
    if not HISTORY_PATH.exists():
        return {}
    try:
        return json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def save_saved_history(payload: dict[str, list[dict[str, str]]]) -> None:
    HISTORY_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def append_repo_history(target: Path, entry: dict[str, str]) -> None:
    payload = load_saved_history()
    key = history_repo_key(target)
    current = list(payload.get(key, []))
    current.append(entry)
    payload[key] = current[-12:]
    save_saved_history(payload)


def render_saved_repo_history_html(target: Path) -> str:
    payload = load_saved_history()
    items = payload.get(history_repo_key(target), [])
    if not items:
        return "<p class='muted'>No saved remediation history for this repo yet.</p>"
    cards = []
    for item in reversed(items[-6:]):
        status = html.escape(item.get("status", "info"))
        cards.append(
            "<div class='card history-card'>"
            f"<p><strong>{html.escape(item.get('label', 'Run'))}</strong> <span class='severity-badge severity-{status}'>{status.title()}</span></p>"
            f"<p class='muted'>{html.escape(item.get('detail', ''))}</p>"
            "</div>"
        )
    return "<div class='grid'>" + "".join(cards) + "</div>"


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
