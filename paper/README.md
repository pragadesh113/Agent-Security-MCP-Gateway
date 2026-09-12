# IEEE conference manuscript

This directory contains an IEEEtran conference-format manuscript about the Phase 2 MCP gateway. It is a submission candidate, not a promise of acceptance. Conference scope, novelty threshold, page limit, anonymity, ethics, artifact, and reference rules still need to be checked for the selected venue.

## Files

- `main.tex` - IEEE conference manuscript.
- `references.bib` - cited primary/official sources.
- `main.pdf` - generated four-page IEEEtran preview.

## Required submission edits

1. Replace the author, affiliation, email, funding, acknowledgments, and repository/artifact placeholders required by the venue.
2. Select the exact conference and apply its page limit, topic fit, double-blind policy, ethics statement, and supplementary-material rules.
3. Refresh every repository count by running the validation commands below. Do not carry forward a number after code or tests change.
4. Keep the manuscript's `UNPROTECTED`, disposable-fixture, synthetic-adapter, and non-forwarding disclosures unless stronger evidence has actually been produced.
5. Add publication-grade adaptive, repeated-trial, real-host, deployment-isolation, and human-approval results before presenting security effectiveness. The current 93-trial harness demonstration validates metric plumbing with deterministic assertions; it is not an empirical 100% prevention result.
6. Verify bibliography metadata and add the anonymized or public artifact URL only when the artifact is ready to share.

## Build

Use a TeX distribution containing `IEEEtran`, `booktabs`, `cite`, `microtype`, `url`, and `xcolor`:

```text
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

Alternatively, upload `main.tex` and `references.bib` to an IEEE conference template project in Overleaf. IEEE's official conference author center recommends its Word/LaTeX templates and provides LaTeX/reference/PDF validation tools:

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

The manuscript snapshot reports 210 unit tests in 21 files, 40 integration tests in 10 files, and 15 structurally complete Phase 2 feature records. The exact security-specific fixtures are documented in `docs/progress.md`; the authoritative design and limitations are in `docs/technical-specification.md`. All reported workflows are disposable. The workspace is not a Git repository, so the current manuscript cannot provide a source-revision attestation.

## Current PDF status

`main.pdf` is a four-page, US-letter IEEEtran preview compiled with Tectonic 0.17.0 and visually inspected page by page. An overfull policy-order equation found during rendering was split and the final four pages were rechecked. The compiler was used from a temporary directory and is not a repository dependency. Recompile with the selected conference's official environment, then run its IEEE PDF eXpress or PDF Checker workflow before submission.
