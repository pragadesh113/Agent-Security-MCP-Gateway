# Evidence and preparation notes

Manuscript: *Effect-Based Bidirectional Authorization for Model Context Protocol Tool Use*.
Prepared September 25, 2026. The executable baseline is commit
`a887ce725d3659cef386cf4e0705fc5e0b37fcca`; paper and documentation edits follow that baseline.

## Fresh verification

Windows 10.0.26200 x64, Node 24.19.0, npm 11.17.0, Vitest 4.1.11.
Build, lint, typecheck, unit, integration, browser, and feature checks all passed.
The test totals are 295 unit tests in 32 files, 66 integration tests in 15 files,
and 4 Chromium workflows. The validator accepted all 21 feature records.
Tests initially encountered sandbox child-process restrictions; approved retries
passed using disposable local resources. Logs are in `tmp/paper-validation/`.

| Manuscript claim | Evidence location | Interpretation |
| --- | --- | --- |
| Three equivalent deletion representations | `test/unit/canonical-policy-v1.test.ts` | Injected trusted resolvers provide semantics; policy outcomes agree. |
| One durable consumption across two connections | `test/integration/postgres-persistence-v1.test.ts` | One forwarding row; rejection of competing consumption and restart replay. |
| 16-way approval race | `test/unit/approval-v1.test.ts` | Process-local fixture, distinct from PostgreSQL evidence. |
| Conservative dispatch recovery | `test/integration/approval-web-postgres-v1.test.ts` | Revoke unconsumed; UNKNOWN consumed/ambiguous; no retry. |
| Result validation and exact forwarding | `test/integration/forwarding-result-mediation-v1.test.ts` | Disposable HTTP peers, redaction, provenance, bounds, cancellation, redirects. |
| Four browser scenarios | `test/browser/approval-ui-v1.spec.ts` | Real Chromium and PostgreSQL; injected Vault responses. |
| Two upstream server checks | `artifacts/open-source-mcp-smoke.json` | Retained September 20 evidence; local-only, not independent operation. |

## Deliberately excluded numerical claims

The 93-record seeded demonstration supplies constant expected attack outcomes and
synthetic latency. Dynamic-trust comparisons are fixture counterfactuals. The
two-adapter integration performs actual initialize requests but supplies policy and
timing observations. These do not establish attack prevention, statistical confidence,
performance improvements, or approval reduction. The September 6 local-evidence
artifact is stale and is not used for current counts.

## Formatting research and exemplars

- [IEEE Author Center templates](https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/authoring-tools-and-templates/)
- [IEEE paper structure](https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/structure-your-paper/)
- [IEEE conference template guidance](https://cai.ieee.org/2025/manuscript-templates-for-conference-proceedings/)
- [Saltzer and Schroeder full text](https://web.mit.edu/Saltzer/www/publications/protection/): explicit protection model, principles, mechanisms, limits.
- [Greshake et al. full text](https://arxiv.org/html/2302.12173v2): threat scenario, attack flow, contributions, limitations.
- [AgentDojo proceedings](https://proceedings.neurips.cc/paper_files/paper/2024/file/97091a5177d8dc64b1da8bf3e1f6fb54-Paper-Datasets_and_Benchmarks_Track.pdf): separate utility/security questions and clear experiment boundaries.

The paper uses IEEEtran conference defaults: Letter, two columns, 10-point body,
numbered references, table captions above, figure captions below, and no page numbers.
It uses three original vector diagrams rather than copied figures. Author, affiliation,
and email space is blank at the user's request. Six primary/official references were
checked; arXiv versions are identified rather than inventing publication venues.

## Publication boundary

The PDF is a finished manuscript, not a submitted or accepted publication. No venue
was specified. Its substantive contribution is design and local conformance
verification; acceptance standards may require comparative adaptive evaluation.
Before submission, fill author details, select the venue, apply its anonymity and
page-limit rules, and complete its required PDF eXpress or PDF Checker workflow.
Any required disclosure of AI-assisted preparation must follow the selected venue's
policy. No approval, signing, publication, or production deployment occurred.
