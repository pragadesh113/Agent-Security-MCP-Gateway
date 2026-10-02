# Originality and source review — technical report

**Review date:** 1 October 2026  
**Reviewed artifact:** [report.md](../report.md)  
**Finding:** source attribution improved; no commercial similarity verdict obtained.

## What this review can establish

The report was inspected for uncited external concepts, generic wording, unsupported
results, and ambiguity about shared project material. Selected passages were searched
against the indexed public web. The opening, contribution explanation, evidence
descriptions, and conclusion were rewritten using the repository's actual behavior
and limitations. Primary references were added for protocol definitions, classical
security principles, and agent-systems background.

This is an editorial and attribution review, not a Turnitin, iThenticate, or other
commercial plagiarism test. No document was uploaded to a similarity service, and
no similarity percentage was calculated. It is not possible to guarantee that every
tool will report zero matches. Protocol method names, API identifiers, commands,
references, and standard security terms can match other documents even when used
appropriately. A similarity result needs passage-by-passage interpretation.

Natural prose was improved through concrete examples, shorter claims, and explicit
evidence provenance. No claim is made about passing an AI-content detector or about
concealing writing assistance. Submission-specific disclosure requirements remain
the author's responsibility.

## Public-web spot checks

These queries sampled the report as it stood before editing. Search providers can
relax quoted queries or return loosely related pages; unrelated results were not
counted as matching passages. Only small query fragments were submitted, not the
complete report.

| Submitted query | Observation in returned results | Editorial response |
|---|---|---|
| `"AI agents are no longer limited to producing text" "Model Context Protocol"` | A short generic opening overlaps wording in indexed [Databricks prose](https://www.databricks.com/blog/mitigating-risk-prompt-injection-ai-agents-databricks) and [K4NUL prose](https://www.k4nul.com/en/development/ai-agent-external-systems/). This is not evidence that the report copied either page. | Replaced the opening with the repository's denied-call demonstration and cited the primary MCP tools specification. |
| `"policy follows the effect" "gateway"` | No matching report passage was identified in the displayed results; loosely related pages were returned. | Replaced the slogan in the executive summary with a two-tool database example and a bounded research question. |
| `"Approval and runtime dispatch are committed together"` | No matching report passage was identified in the displayed results. | Retained the implementation fact; its authority is the repository implementation and evidence. |
| `"tested components do not justify a production-protection claim"` | No matching report passage was identified in the displayed results. | Rewrote the conclusion around the precise local claim and remaining assurance work. |

These four samples are not an exhaustive sentence search. The search index does not
cover private student submissions, publisher databases, unpublished documents, every
webpage, or all versions of a source. Search results do not establish who wrote a
phrase first. Absence of a displayed match is not proof of originality.

## Attribution and provenance changes

| Material | Source now identified | Reason |
|---|---|---|
| MCP initialization, version negotiation, and capabilities | [MCP lifecycle specification, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle) | Protocol behavior is established externally. |
| `tools/list`, `tools/call`, tool metadata, and protocol security guidance | [MCP tools specification, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) | Distinguishes protocol definitions from added gateway rules. |
| Complete mediation, fail-safe defaults, and least privilege | [Saltzer and Schroeder, 1975](https://web.mit.edu/Saltzer/www/publications/protection/Basic.html) | Established concepts are credited, rather than claimed as inventions. |
| Security consequences of agent tool/environment access | [He et al., 2024 preprint](https://arxiv.org/abs/2406.08689) | Connects motivation to primary systems-security work. |
| Test counts and feature completion | [docs/progress.md](../docs/progress.md) and [docs/featurelist.json](../docs/featurelist.json) | Uses dated repository checkpoints, not newly measured effectiveness. |
| SBOM, manifest, reproducible build, and dependency audit counts | [docs/progress.md](../docs/progress.md) and [release-gate audit](../docs/release-gate-audit.md) | Labels 20 September 2026 evidence and keeps production gates separate. |
| Report/paper component names, decisions, and results | Introductory project-provenance statement in the report | The two documents describe the same project and naturally share technical material. |

The report does not copy extended passages from these external sources. New background
paragraphs paraphrase the concepts and link to their sources. Source verification
was limited to the linked primary pages and repository evidence; this review does
not independently repeat the experiments in cited papers.

## Submission check still needed

Run the final rendered report and final rendered paper through the similarity tool
required by the receiving institution, using its actual bibliography/quotation
settings. Review the matched passages and add attribution or rewrite any problematic
close paraphrase. Retain the tool's dated report separately from this review. An
author should also check the venue's rules for publishing project documentation and
a related manuscript with shared content.

The companion paper is being reviewed separately; this note documents only the
report checks above and must not be treated as a paper-wide clearance certificate.
