"""Render an inventory as one self-contained, offline HTML file.

Security properties of the output:
  * No network access. The Content Security Policy sets default-src 'none'
    and the page loads nothing external, so it cannot leak data when opened.
  * Scripts run only if their SHA-256 matches, computed here at render time.
  * Captured strings are embedded as JSON inside a non-executing script
    element, with <, >, & and line separators escaped, and the page script
    places them with textContent only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from importlib import resources

from keelmap.report.view import build_view

CYTOSCAPE_SHA256 = "83e8c54a6bec655bfd81df07df605649c268af69aeca67a5ea2da54ea42dac81"
_PLACEHOLDER = re.compile(r"\{\{(CSP|DATA|CYTOSCAPE|APP)\}\}")


def _read(name: str) -> str:
    return (resources.files("keelmap.report") / name).read_text(encoding="utf-8")


def _script_hash(code: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(code.encode("utf-8")).digest()).decode() + "'"


def safe_json(obj: object) -> str:
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def render_html(inventory: dict) -> str:
    cytoscape = _read("vendor/cytoscape.min.js")
    if hashlib.sha256(cytoscape.encode("utf-8")).hexdigest() != CYTOSCAPE_SHA256:
        raise RuntimeError("vendored cytoscape.min.js does not match its recorded hash")
    app = _read("app.js")
    for code in (cytoscape, app):
        if "</script" in code.lower():
            raise RuntimeError("script contains a closing script tag")
    csp = ("default-src 'none'; "
           f"script-src {_script_hash(cytoscape)} {_script_hash(app)}; "
           "style-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; "
           "base-uri 'none'; form-action 'none'")
    parts = {"CSP": csp, "DATA": safe_json(build_view(inventory)), "CYTOSCAPE": cytoscape, "APP": app}
    # One pass over the template only, so text inside DATA can never be read as a placeholder.
    return _PLACEHOLDER.sub(lambda m: parts[m.group(1)], _read("template.html"))
