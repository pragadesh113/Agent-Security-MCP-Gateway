# IEEE conference manuscript

This directory contains an IEEEtran conference-format manuscript about the Phase 2 MCP gateway. It is a submission candidate, not a promise of acceptance. Conference scope, novelty threshold, page limit, anonymity, ethics, artifact, and reference rules still need to be checked for the selected venue.

## Files

- `main.tex` - IEEE conference manuscript.
- `references.bib` - cited primary/official sources.
- `main.pdf` - generated eight-page IEEEtran conference manuscript, including references.
- `figures/` - original vector diagrams used by the manuscript.
- `evidence-notes.md` - source evidence, verification boundaries, and publication preparation notes.
- `originality-review.md` - source-attribution checks and the limits of sampled similarity screening.
- `../images/` - 24 original diagrams, tables, and charts, with a gallery, reproducible generator, and source manifest. Three additional full-width diagrams are included in the manuscript.

## Required submission edits

1. Replace the author, affiliation, email, funding, acknowledgments, and repository/artifact placeholders required by the venue.
2. Select the exact conference and apply its page limit, topic fit, double-blind policy, ethics statement, and supplementary-material rules.
3. Refresh every repository count by running the validation commands below. Do not carry forward a number after code or tests change.
4. Keep the manuscript's `UNPROTECTED`, disposable-fixture, synthetic-adapter, and non-forwarding disclosures unless stronger evidence has actually been produced.
5. Add publication-grade adaptive, repeated-trial, real-host, deployment-isolation, and human-approval results before presenting security effectiveness. The current 93-record harness demonstration validates metric plumbing with deterministic assertions; it is not an empirical prevention result.
6. Verify bibliography metadata and add the anonymized or public artifact URL only when the artifact is ready to share.

## Build

Use a TeX distribution containing `IEEEtran`, `booktabs`, `cite`, `microtype`, `url`, and `xcolor`:

```text
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

Alternatively, upload `main.tex`, `references.bib`, `figures/`, and the referenced `../images/` PDFs with the same relative layout to an IEEE conference template project in Overleaf. If a service flattens the project, adjust the image paths accordingly. IEEE's official conference author center recommends its Word/LaTeX templates and provides LaTeX/reference/PDF validation tools:

- https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/authoring-tools-and-templates/
- https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/structure-your-paper/

Before submission, run the IEEE LaTeX Analyzer and the venue's PDF/eXpress or PDF Checker workflow when required. Do not change the document class away from `\documentclass[conference]{IEEEtran}` unless the venue supplies a different official template.

The checked-in preview was compiled with Tectonic 0.17.0:

```text
tectonic main.tex
```

## Reproduce repository evidence

From the repository root:

```text
npm run build
npm run lint
npm run typecheck
npm test
npm run test:integration
npm run validate:features
```

The current manuscript snapshot reports 295 unit tests in 32 files, 66 integration tests in 15 files, four Chromium workflows, and 21 validated Phase 2 feature records. The exact security-specific fixtures are documented in `paper/evidence-notes.md`; the authoritative design and limitations are in `docs/technical-specification.md`. All reported workflows are disposable or explicitly local-only. The manuscript records source revision `a887ce725d3659cef386cf4e0705fc5e0b37fcca`.

## Current PDF status

`main.pdf` was rebuilt on October 1, 2026 as an eight-page, US-letter IEEEtran conference manuscript with six figures and three tables. All eight rendered pages were inspected, with no clipped figures or unresolved citations/references observed. The three new full-width diagrams show conditional representation invariance, two-consumer approval contention, and independent result governance. Figure footers are cropped in the manuscript to reduce redundant whitespace; the full original exports remain in `../images/`.

The built-in editor was opened, but its compiler could not initialize platform directories. The existing cached Tectonic 0.17.0 compiler succeeded without installing a TeX distribution. It emitted underfull spacing warnings and a Fontconfig configuration warning; no overfull boxes or unresolved-reference warnings remained. Recompile with the selected conference's official environment and page limit, then run its IEEE PDF eXpress or PDF Checker workflow before submission.

The prose and bibliography received an attribution review; sampled web searches and exact 12-token screening against the two supplied source PDFs do not constitute a proprietary plagiarism test. See `../docs/document-originality-and-visuals.md` for the complete verification boundary. The September counts above remain historical: October repository checks passed 333 unit and 74 integration tests, while lint reported two existing diagnostics in the unrelated uncommitted resolver extension. No new effectiveness study or browser/release validation is claimed by this document update.
