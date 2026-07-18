"""Session-scoped findings accumulator and Markdown/HTML/JSON/CSV report rendering."""
import csv
import html
import io
import json
from datetime import datetime, timezone

from desisherlock.utils import REPORTS_DIR, ensure_config_dir


class Session:
    """Accumulates command results across a REPL session, keyed by command name."""

    def __init__(self):
        self.findings = {}
        self.started_at = datetime.now(timezone.utc).isoformat()

    def record(self, command, result):
        self.findings.setdefault(command, []).append(result)

    def is_empty(self):
        return not self.findings


def _render_markdown(session):
    lines = [
        "# Desisherlock Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Session started: {session.started_at}",
        "",
    ]
    if session.is_empty():
        lines.append("_No findings recorded this session._")
        return "\n".join(lines)

    for command, entries in session.findings.items():
        lines.append(f"## {command}")
        lines.append("")
        for entry in entries:
            lines.append("```json")
            lines.append(json.dumps(entry, indent=2, default=str))
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def _render_html(session):
    parts = [
        "<html><head><meta charset='utf-8'><title>Desisherlock Report</title></head><body>",
        "<h1>Desisherlock Report</h1>",
        f"<p>Generated: {html.escape(datetime.now(timezone.utc).isoformat())}</p>",
        f"<p>Session started: {html.escape(session.started_at)}</p>",
    ]
    if session.is_empty():
        parts.append("<p><em>No findings recorded this session.</em></p>")
    else:
        for command, entries in session.findings.items():
            parts.append(f"<h2>{html.escape(command)}</h2>")
            for entry in entries:
                escaped = html.escape(json.dumps(entry, indent=2, default=str))
                parts.append(f"<pre>{escaped}</pre>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _render_json(session):
    return json.dumps(
        {
            "started_at": session.started_at,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": session.findings,
        },
        indent=2,
        default=str,
    )


def _render_csv(session):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["command", "entry_index", "result_json"])
    for command, entries in session.findings.items():
        for index, entry in enumerate(entries):
            writer.writerow([command, index, json.dumps(entry, default=str)])
    return buf.getvalue()


_RENDERERS = {
    "md": (_render_markdown, "md"),
    "html": (_render_html, "html"),
    "json": (_render_json, "json"),
    "csv": (_render_csv, "csv"),
}


def render(session, fmt="md"):
    fmt = (fmt or "md").lower()
    if fmt not in _RENDERERS:
        raise ValueError(f"Unknown report format: {fmt} (expected md, html, json, or csv)")
    renderer, _ = _RENDERERS[fmt]
    return renderer(session)


def save(session, fmt="md"):
    """Render and save the report under ~/.desisherlock/reports/. Returns the path."""
    ensure_config_dir()
    fmt = (fmt or "md").lower()
    if fmt not in _RENDERERS:
        raise ValueError(f"Unknown report format: {fmt} (expected md, html, json, or csv)")
    _, ext = _RENDERERS[fmt]
    content = render(session, fmt)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORTS_DIR / f"desisherlock-report-{timestamp}.{ext}"
    with open(path, "w") as f:
        f.write(content)
    return str(path)
