#!/usr/bin/env python3
"""Render the versioned HoneyMesh Markdown manual to a public PDF."""

from pathlib import Path
import re
import subprocess
import tempfile

from markdown_it import MarkdownIt


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/HoneyMesh-Operator-Manual-v2.3.6-rc2.md"
OUTPUT = ROOT / "public/HoneyMesh-Operator-Manual-v2.3.6-rc2.pdf"


def main() -> None:
    source = SOURCE.read_text()
    source = re.sub(r"^\*\*(\d+\. .+)\*\*$", r"## \1", source, flags=re.M)
    html_body = MarkdownIt("commonmark", {"html": False}).render(source)
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>HoneyMesh Operator Manual 2.3.6-rc2</title><style>
@page { size: A4; margin: 19mm 17mm 20mm; }
body { font: 10pt/1.47 Arial, sans-serif; color: #192a43; max-width: 100%; }
* { box-sizing: border-box; }
.cover { height: 250mm; break-after: page; background: #111f35; color: #fff;
  margin: -19mm -17mm 0; padding: 30mm 20mm; }
.cover .eyebrow { color: #ffb326; font-size: 9pt; font-weight: bold;
  text-transform: uppercase; letter-spacing: 2pt; }
.cover .rule { width: 70mm; height: 5pt; margin: 22mm 0 32mm; background: #ffae18; }
.cover h1 { font-size: 42pt; line-height: 1.05; color: #fff; margin: 0 0 12mm; }
.cover .version { color: #ffb326; font-size: 18pt; font-weight: bold; }
.cover .desc { max-width: 130mm; color: #bdd0e8; font-size: 13pt; line-height: 1.55; }
.cover .date { margin-top: 55mm; color: #bdd0e8; font-size: 10pt; }
article > h1:first-child { display: none; }
h1, h2, h3 { color: #132641; line-height: 1.16; break-after: avoid; }
h2 { font-size: 19pt; margin: 22pt 0 10pt; border-top: 2pt solid #f4a000; padding-top: 12pt; }
h3 { font-size: 12pt; margin: 15pt 0 6pt; }
p, ul, ol, pre, table { margin-top: 0; margin-bottom: 10pt; }
p, li { orphans: 3; widows: 3; }
li { margin: 0 0 4pt; }
ul, ol { padding-left: 18pt; }
strong { color: #132641; }
code { font: 8pt/1.3 'DejaVu Sans Mono', monospace; overflow-wrap: anywhere; }
pre { background: #14243c; color: #f3f7fd; padding: 10pt 12pt;
  border-radius: 5pt; white-space: pre-wrap; overflow-wrap: anywhere;
  font: 8pt/1.4 'DejaVu Sans Mono', monospace; break-inside: avoid; }
pre code { color: inherit; }
blockquote { border-left: 3pt solid #f4a000; padding-left: 10pt; color: #3e5571; }
hr { border: 0; border-bottom: 1px solid #d7e0eb; margin: 17pt 0; }
a { color: #a66a00; text-decoration: underline; }
table { width: 100%; border-collapse: collapse; }
td,th { padding: 5pt 7pt; border-bottom: 1px solid #dce4ee; }
th { color: #fff; background: #172943; }
</style></head><body><div class="cover"><div class="eyebrow">HoneyMesh / Operator documentation</div>
<div class="rule"></div><h1>Operate the<br>Iron Hive.</h1>
<div class="version">HoneyMesh 2.3.6-rc2</div>
<p class="desc">Installation, local protection, eBPF/XDP enforcement, trusted peers, and Exchange sharing.</p>
<div class="date">Linux AMD64 release candidate<br>30 October 2026<br>honeymesh.io</div></div>
<article>""" + html_body + "</article></body></html>"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "manual.html"
        path.write_text(html)
        subprocess.run(
            ["google-chrome", "--headless", "--no-sandbox", "--disable-gpu",
             "--no-pdf-header-footer", f"--print-to-pdf={OUTPUT}", path.as_uri()],
            check=True, capture_output=True, text=True,
        )
    print(OUTPUT)


if __name__ == "__main__":
    main()
