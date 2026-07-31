from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path


STATIC_DIR = Path("sub2api_recorder/static")


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.script_sources: list[str | None] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.append(str(attributes["id"]))
        if tag == "script":
            self.script_sources.append(attributes.get("src"))


def test_audit_ui_controls_match_javascript_contract() -> None:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    javascript = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_DIR / "styles.css").read_text(encoding="utf-8")
    parser = _PageParser()
    parser.feed(html)

    assert len(parser.ids) == len(set(parser.ids))
    required_ids = set(
        re.findall(r'document\.querySelector\("#([a-z0-9_-]+)"\)', javascript)
    )
    assert required_ids <= set(parser.ids)
    assert parser.script_sources == ["static/app.js"]
    assert "<style" not in html
    assert "REQUEST OBSERVABILITY" not in html
    assert 'id="page-title"' not in html
    assert 'data-range="today" class="is-active"' in html
    assert "setRange(\"today\")" in javascript
    assert "aria-live=\"polite\"" in html
    assert "`${auditBase}/api/context`" in javascript
    assert 'const auditBase = window.location.pathname.startsWith("/admin/audit/")' in javascript
    assert "#viewer-label" in javascript
    assert "#username-filter-field" in javascript
    assert "#audit-preference-control" in javascript
    assert "#audit-enabled" in javascript
    assert "#audit-disabled-notice" in javascript
    assert 'method: "PUT"' in javascript
    assert 'timeZone: timezone' in javascript
    assert re.search(
        r"\[hidden\]\s*\{\s*display:\s*none\s*!important;\s*\}",
        stylesheet,
    )
