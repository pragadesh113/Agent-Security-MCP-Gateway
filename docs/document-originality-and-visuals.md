# Report and manuscript verification

Review date: 1 October 2026. Documents: [technical report](../report.md) and
[research manuscript](../paper/main.tex).

## Originality finding

The documents received an editorial review, primary-source checks, sampled public-web
phrase searches, and a reproducible local exact-phrase screen. No commercial or
institutional similarity service was run. A pass across every plagiarism tool, zero
similarity, and an authorship-detector result cannot be certified by this work.

The report's generic opening was replaced with its actual denied-call demonstration.
External protocol definitions and established security principles now have explicit
sources. The paper's related work distinguishes Progent's configurable policy-expansion
approval from this project's single-invocation approval and explains MCIP's contextual
flow and learned guarding. Its newer resolver corpus is described as unreviewed
development material, with no measured accuracy or attack-prevention claim.

The local screen compares normalized 12-token windows from each document with extracted
text from both supplied source papers: `docs/Security of AI Agents.pdf` and
`docs/Agentic_AI_Security_Threats_Defenses_Evaluation_and_Open_Challenges.pdf`.
It found zero matching windows in each of the four document/source pairs. This is a
specific exact-phrase observation, not a plagiarism percentage. It cannot detect close
paraphrase, copied ideas, translations, images, unindexed submissions, or extraction
errors. Necessary citations and technical terms should be retained even if a tool
counts them as similar.

Reproduce the screen using `scripts/check-document-originality.py` with Python and
`pypdf`. The [JSON record](../report-assets/originality-local-audit.json) records input
hashes and limits. The detailed [report review](../report-assets/originality-review.md)
and [paper review](../paper/originality-review.md) preserve the sampled queries and
primary-source links. No complete document was uploaded to a plagiarism service.

The report and paper describe the same project. Their shared rules, component names,
and local evidence are acknowledged as project material, rather than presented as
independent research outputs. Their final rendered versions still require the receiving
institution's authorized similarity check and review of substantive matches.

## Visual and evidence discipline

Original figures and source data are stored in [images](../images/README.md), with a
[gallery](../images/gallery.html). Diagrams explain the implementation; they do not
demonstrate security effectiveness. Charts use dated repository evidence or the
candidate corpus composition. Tests are not independent attacks, interoperability
tool counts are not coverage, and a development corpus is not held-out ground truth.

The supplied illustrations replace generic decoration with concrete request paths,
approval transitions, custody boundaries, results, and evidence limitations. Writing
was edited for specificity and readable explanation. No AI-detector evasion or
guarantee about perceived authorship is claimed.

## Current repository checks

- Build and type checking passed.
- Unit tests passed: 333 tests in 33 files.
- Integration tests passed on retry: 74 tests in 16 files. The first unsandboxed run
  had a disposable PostgreSQL startup timeout; it is retained as a failed invocation.
- Feature validation passed: all 21 existing Phase 2 records.
- Lint failed on two existing diagnostics in the uncommitted resolver extension:
  deprecated `z.number().finite()` at `src/evaluation/resolver-corpus-v1.ts:79` and
  a restricted numeric template expression at line 110. That source was outside
  this documentation task and was preserved.
- Initial test startups were blocked by sandbox `spawn EPERM`; approved retries
  executed the disposable suites.

The documents' September regression, browser, interoperability, and release counts
remain dated historical observations. The October tests do not refresh the release
manifest, certify production deployment, or validate a research effectiveness study.
Browser, Vault, Docker, release, and new resolver experiments were not rerun in this
documentation task. Coverage remains `UNPROTECTED`; protected forwarding is disabled.

## Paper rendering

The built-in LaTeX editor was opened, but its compiler failed to initialize standard
platform directories. The existing cached workspace Tectonic compiler successfully
compiled the manuscript with its bibliography and figures. Final figure integration,
page rendering, and layout inspection passed for all eight pages, six figures, three
tables, and six bibliography entries. No unresolved references or clipped figures
were observed. Underfull spacing and Fontconfig warnings remain; there are no
overfull-box warnings in the final build. The source remains editable in the built-in
editor. All 24 visuals accompany the report; three supplement the manuscript's
existing three diagrams.

## Remaining submission work

Use the institution's required tool on the exact final report and paper. Review each
substantive match with its source; properly quoted or cited text, reference metadata,
technical terminology, and reuse of project material require contextual judgment.
Complete author details, selected-venue formatting, and any required assistance
disclosure. Independent corpus labels, held-out research evaluation, and production
assurance remain separate unfinished work.
