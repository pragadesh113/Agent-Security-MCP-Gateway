# Original report and manuscript visual atlas

Prepared October 1, 2026. Open [gallery.html](gallery.html) for all 24 assets with
captions, document placement suggestions and download links. The
[contact sheet](contact-sheet.png) provides a quick overview. All diagrams are
original geometric artwork created from this repository's documented design;
no external illustrations or stock assets were copied.

Every numbered figure has three formats:

- **SVG:** editable vector geometry and selectable text, ideal for HTML.
- **PDF:** vector artwork for LaTeX and publication export.
- **PNG:** 2400 × 1440 pixels for Markdown and document insertion.

Tables and bar charts also have editable CSV data. Captions, source paths and
report/paper section mappings are in [manifest.json](manifest.json). Source file
SHA-256 hashes identify the repository evidence read by the generator. These
hashes are provenance aids, not independent verification of the underlying claims.

## Suggested manuscript figures

Use a small selection; placing every figure in a conference paper would crowd the
argument. The wide six-step figures should span both columns. Retain the existing
compact manuscript figures if a single-column version is required.

| Figure | Placement | Contribution |
| --- | --- | --- |
| `01-gateway-architecture.pdf` | Reference monitor design | Bidirectional request/result boundary |
| `05-representation-invariance.pdf` | Semantic equivalence or local RQ1 | Same effect does not transfer exact approval |
| `09-approval-concurrency.pdf` | Single-use approval or local RQ2 | Two connections and one durable consumption |
| `10-restart-recovery.pdf` | Recovery | Revoked versus unknown, with no automatic retry |
| `14-bypass-trust-boundaries.pdf` | Threat model or coverage | MCP/native/direct separation |
| `23-candidate-corpus-inventory.pdf` | Future-study context, only if discussed | Development inventory; explicitly unreviewed |

The technical report can use the remaining assets beside their respective sections,
following the manifest. Images should supplement the explanation, rather than
repeat every table and paragraph.

## Numerical evidence boundaries

- Figure 21 uses the **September 25, 2026** manuscript snapshot: 295 unit tests,
  66 integration tests and four browser workflows. It is historical, and does not
  assert the current test inventory after later resolver work.
- Figure 22 reads `artifacts/open-source-mcp-smoke.json`: discovery advertises 13
  Everything MCP tools and 26 Playwright MCP tools in the retained September 20
  local-only observations. These are not independently operated hosts.
- Figure 23 reads `research/resolver/corpus-v1.json`: 50 candidate development calls
  (24 benign intent, 26 adversarial intent), with 30 families. Author-produced
  labels are unreviewed and there are no held-out cases. This is neither an
  accuracy chart nor an attack-effectiveness result.
- No synthetic demonstration latency, fixture attack-success rate, fabricated
  confidence interval, comparative performance bar or human-study metric appears.
- Coverage remains `UNPROTECTED`; protected production forwarding stays disabled.

## Rebuilding and checking

Run `python images/generate_visuals.py` from the repository root with Pillow and
ReportLab installed. The script uses Windows Arial fonts for raster width checks,
Arial/Helvetica-compatible SVG text and PDF Helvetica. It requires no network.

The generator checks text against the canvas, wrapped text against each box,
table height, SVG XML parsing and PNG dimensions, and regenerates the contact
sheet. [visual-qa.json](visual-qa.json) records those structural checks. The contact
sheet and representative full-resolution figures were visually inspected for
legibility, unclipped labels and arrow placement. Text is selectable in the vector
exports; the PNGs provide a fallback for applications with different installed fonts.

These are technical illustrations with restrained typography and explicit evidence
labels. Their originality does not imply a plagiarism-tool certificate for the prose
or a guarantee about automated authorship classifiers.
