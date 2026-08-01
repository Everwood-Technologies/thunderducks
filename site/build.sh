#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/_site"
rm -rf "$OUT"
mkdir -p "$OUT/assets" "$OUT/docs"
cp "$ROOT/index.html" "$OUT/"
cp "$ROOT/assets/site.css" "$OUT/assets/"

# docs index
cat > "$OUT/docs/index.html" << 'HTML'
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Thunderducks docs</title>
<link rel="stylesheet" href="../assets/site.css"/>
</head><body>
<header class="wrap"><p class="brand">🦆 Thunderducks docs</p>
<nav><a href="../">Home</a><a href="https://github.com/Everwood-Technologies/thunderducks">GitHub</a></nav>
</header>
<main class="wrap docs-body">
<h1>Documentation</h1>
<ul class="docs">
<li><a href="threat-model.html">Threat model</a></li>
<li><a href="threat-model-diff.html">Threat model ↔ impl diff</a></li>
<li><a href="architecture.html">Architecture</a></li>
<li><a href="mvp-accept.html">MVP accept</a></li>
<li><a href="harness.html">Operator harness</a></li>
<li><a href="bench.html">Benches</a></li>
<li><a href="post-mvp-backlog.html">Post-MVP backlog</a></li>
<li><a href="site-and-pages.html">Site & Pages plan</a></li>
<li><a href="SECURITY.html">Security policy</a></li>
<li><a href="README.html">README</a></li>
</ul>
</main></body></html>
HTML

python3 - <<'PY'
from pathlib import Path
import html
import re

root = Path("site")
out = root / "_site" / "docs"
src = root / "docs"

def md_to_html(md: str) -> str:
    # Minimal, boring converter: escape + light structure
    lines = md.splitlines()
    out_lines = []
    in_code = False
    in_list = False
    for line in lines:
        if line.startswith("```"):
            if not in_code:
                if in_list:
                    out_lines.append("</ul>")
                    in_list = False
                out_lines.append("<pre><code>")
                in_code = True
            else:
                out_lines.append("</code></pre>")
                in_code = False
            continue
        if in_code:
            out_lines.append(html.escape(line))
            continue
        if re.match(r"^### ", line):
            if in_list:
                out_lines.append("</ul>"); in_list = False
            out_lines.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif re.match(r"^## ", line):
            if in_list:
                out_lines.append("</ul>"); in_list = False
            out_lines.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif re.match(r"^# ", line):
            if in_list:
                out_lines.append("</ul>"); in_list = False
            out_lines.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif re.match(r"^[-*] ", line):
            if not in_list:
                out_lines.append("<ul>"); in_list = True
            item = line[2:]
            # bare links
            item = re.sub(r"`([^`]+)`", lambda m: f"<code>{html.escape(m.group(1))}</code>", item)
            item = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", item)
            out_lines.append(f"<li>{item}</li>")
        elif line.strip() == "":
            if in_list:
                out_lines.append("</ul>"); in_list = False
            out_lines.append("")
        elif line.strip().startswith("|") and "---" not in line:
            out_lines.append(f"<pre>{html.escape(line)}</pre>")
        else:
            if in_list:
                out_lines.append("</ul>"); in_list = False
            t = html.escape(line)
            t = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", t)
            t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
            out_lines.append(f"<p>{t}</p>")
    if in_list:
        out_lines.append("</ul>")
    if in_code:
        out_lines.append("</code></pre>")
    return "\n".join(out_lines)

template = """<!doctype html>
<html lang=\"en\"><head>
<meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>
<title>{title} — Thunderducks</title>
<link rel=\"stylesheet\" href=\"../assets/site.css\"/>
</head><body>
<header class=\"wrap\"><p class=\"brand\">🦆 Thunderducks</p>
<nav><a href=\"../\">Home</a><a href=\"./\" >Docs</a><a href=\"https://github.com/Everwood-Technologies/thunderducks\">GitHub</a></nav>
</header>
<main class=\"wrap docs-body\">
<div class=\"docs-nav\"><a href=\"./\">← Docs index</a></div>
{body}
</main>
<footer class=\"wrap\"><p>Source of truth lives in the repo <code>docs/</code>.</p></footer>
</body></html>
"""

for md_path in sorted(src.glob("*.md")):
    body = md_to_html(md_path.read_text())
    title = md_path.stem
    html_path = out / f"{md_path.stem}.html"
    # SECURITY.md becomes SECURITY.html via stem
    html_path.write_text(template.format(title=html.escape(title), body=body))
    print("wrote", html_path)

# LICENSE
lic = src / "LICENSE.txt"
if lic.exists():
    body = f"<h1>License</h1><pre>{html.escape(lic.read_text())}</pre>"
    (out / "LICENSE.html").write_text(template.format(title="License", body=body))
print("build ok")
PY
