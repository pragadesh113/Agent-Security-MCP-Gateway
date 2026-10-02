# Manuscript originality and attribution review

Reviewed October 1, 2026. Scope: `main.tex` and `references.bib`, including the
existing working-tree manuscript. This is an editorial and source-attribution
review, not a Turnitin, iThenticate, or other proprietary similarity certificate.
No manuscript was uploaded to an external plagiarism service.

## Finding and limits

The inspected manuscript explains the project's own design and local evidence and
attributes the principal external concepts. This review did not identify a passage
that warranted treatment as an unattributed quotation. That finding is bounded by
the sources and sampled searches below. It cannot establish zero plagiarism or
predict a pass, percentage, or result from every similarity tool.

Similarity and plagiarism are different questions. Reference titles, protocol names,
security terminology, and correctly attributed descriptions can produce legitimate
matches. Proprietary indexes may also contain student submissions and unpublished
material unavailable to public search. Check the final rendered submission through
the institution's authorized tool, inspect each substantive match, and apply its
rules for quotations, references, and reuse of earlier work. Do not remove a necessary
citation or distort a technical term simply to lower a similarity number.

## Primary-source checks

| Source | Check and manuscript treatment |
| --- | --- |
| [MCP revision 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18) | Verified the pinned revision, client/server exchange, discovery-related features, and specification's implementation responsibility for consent and access control. The paper distinguishes interoperability from authorization. |
| [Greshake et al., version 2](https://arxiv.org/abs/2302.12173v2) | Verified title, six authors, 2023 version, and indirect-injection subject. The introductory explanation is attributed and uses the project's own workspace example. |
| [Saltzer and Schroeder](https://web.mit.edu/Saltzer/www/publications/protection/), [basic principles](https://web.mit.edu/Saltzer/www/publications/protection/Basic.html) | Checked the authors' retained text for least privilege, complete mediation, and fail-safe defaults. These established concepts remain cited; no novelty claim is attached to them. |
| [AgentDojo](https://arxiv.org/abs/2406.13352) | Verified title, authors, 2024 version, and evaluation of utility alongside security. The paper borrows the evaluation motivation with attribution, not AgentDojo's measured outcomes. |
| [Progent, version 3](https://arxiv.org/html/2504.11703v3) | Verified seven authors, May 14, 2026 version, symbolic tool rules, SMT policy comparison, and configurable expansion approver. Corrected the manuscript to distinguish policy-expansion approval from this project's single-invocation approval. |
| [MCIP proceedings record](https://aclanthology.org/2025.emnlp-main.62/), [version 7 text](https://arxiv.org/html/2505.14590v7) | Verified proceedings metadata and contextual-flow/learned-guard emphasis. Added that explanation and explicitly retained the absence of a reproduced comparison. The BibTeX follows the Anthology record, including its author-name spelling and pagination. |

Bibliographic URLs were added for stable retrieval. Progent is cited as the inspected
arXiv version rather than assigning it an unverified publication venue. The MCP access
note now records this review date. No numerical result from these sources was imported
as this project's result.

## Sampled public phrase searches

Public searches used these exact quoted manuscript fragments:

- `Semantic equivalence does not transfer approval`
- `coverage derived from evidence of exclusive mediation`
- `A lost connection can leave the effect unknown`
- `Tool-using language-model agents can express the same harmful effect`
- `The trusted computing base comprises the gateway runtime`

No relevant exact-match passage appeared in the inspected returned results. Some
queries returned loosely related or unrelated pages despite quotation marks; those
results are not an exhaustive exact-match test. No conclusion about a proprietary
index or a numerical similarity score follows from this sample. Search queries
transmitted these short fragments to the search provider, not the whole document.

## Editorial and evidence corrections

The related-work explanation now names the mechanism each prior work actually uses
and distinguishes an approved policy expansion from one exact approved invocation.
This avoids presenting established external enforcement as a new invention. MCIP's
contextual trajectories and learned guarding are described with a citation rather
than compressed into a generic label.

The manuscript now acknowledges the subsequent workspace-file resolver and its
50-call development corpus (24 benign, 26 adversarial, 30 families). Candidate labels
are explicitly unreviewed, there is no held-out split, and no accuracy or attack
prevention result is claimed. The earlier September 25 regression counts remain
historical evidence and are not relabelled as validation of this later extension.
The resolver's observation of file state is not represented as a race-free execution
binding or deployed protection.

Writing changes favor specific mechanisms, examples, and measured limitations. They
do not attempt to evade an AI detector, guarantee a particular authorship impression,
or hide assistance. Any required authorship or AI-assistance disclosure depends on
the selected institution or venue and should be completed before submission.

## Final verification handoff

The main task must compile and inspect the final manuscript after integrating figures,
check all citations and figure references, and retain the rendered output alongside
the source. This review does not certify the rendering or rerun repository tests.
Recheck similarity against that exact final version: later prose or image captions
can change the result. Review corpus labels independently before using a resolver
development chart as a research accuracy or effectiveness result.
