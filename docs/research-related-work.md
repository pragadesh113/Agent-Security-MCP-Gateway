# Closest-work comparison for protocol v0.1

Checked 2026-09-27 against the primary versions below. This is a focused comparison
of the two systems named in [the research plan](addon-md.txt), not an exhaustive
novelty review. “Not established” describes the inspected paper's evidence; it does
not assert that a mechanism is absent from all releases or related work.

| Dimension | Progent v3 | MCIP v7 | Evidence this project still needs |
| --- | --- | --- | --- |
| Representation | Tool identifiers and typed arguments; “Effect” denotes allow/forbid | Sender, recipient, data subject, information type, transmission principle | Independent resource/effect labels across equivalent tools and actual state |
| Enforcement | Deterministic privilege rules, forbid precedence, default blocking, schema checks and SMT comparison | Learned Guardian risk detection/classification | Fair comparison under equivalent policy intent |
| Approval | Configurable approval for policy expansion | Consent represented as a transmission principle | Exact expiring approval bound to resources and one durable dispatch under substitution |
| Returned data | Observations inform policy updates; deterministic redaction/quarantine not established | Tool returns enter trajectories; deterministic pre-delivery quarantine not established | Observed leakage and utility with result-governance ablation |
| Evaluation | AgentDojo/ASB, MCP-backed AgentDojo, attack success and benign utility | Synthetic contextual-risk data, risk classification, BFCL-v3 utility | Paired executed effects and complete-trajectory observations |
| Limits relevant here | Text-output and within-privilege attacks excluded; main benchmark automatically accepts expansions | Real-world log collection unavailable; classification does not establish prevention of executed effects | Label provenance, faithful baseline configuration, and bounded claims |

## Primary sources and reproduction status

- **Progent:** [Securing AI Agents with Privilege Control, v3, 14 May 2026](https://arxiv.org/html/2504.11703v3),
  especially sections 3–8; [official repository](https://github.com/sunblaze-ucb/progent).
  The paper and repository README were inspected. No implementation audit, pinned
  installation, or reproduced experiment was performed in this session.
- **MCIP:** [Model Contextual Integrity Protocol, v7, 29 September 2025](https://arxiv.org/html/2505.14590v7),
  especially sections 3 and 5–7; [official repository](https://github.com/HKUST-KnowComp/MCIP).
  The paper and repository README were inspected. No model evaluation was run.

Progent is the first candidate enforcement comparator. MCIP informs the contextual
risk taxonomy; its classifier metrics must not be compared directly to downstream
attack prevention. Before experiments, pin available artifacts, map policies and
approval semantics, record installation/reproduction failures, and decide which
comparisons are defensible. Neither a paper comparison nor missing evidence in a
paper proves this project's novelty.

## Local evidence boundary

The following inspected implementation and tests motivate the protocol's open questions:

- [Canonicalizer](../src/action-normalizer/canonical-action-v1.ts): accepts resolver
  output; lexical normalization does not independently establish filesystem identity.
- [Required-analyzer registry](../src/action-normalizer/required-analyzers-v1.ts):
  validates category/syntax contracts and quarantines unknown analysis; the registry
  itself is not an implementation of each semantic analyzer.
- [Canonical-policy tests](../test/unit/canonical-policy-v1.test.ts): equivalent
  deletion cases inject expected semantics; they demonstrate policy consistency
  conditional on those semantics.
- [Approved executor](../src/runtime/client-tool-call-v1.ts) and
  [PostgreSQL loader](../src/persistence/postgres-trajectory-store-v1.ts): reload and
  bind stored action/decision authority. This does not establish fresh semantic
  resolution of aliases or current filesystem state before consumption.

The proposed study is specified in [research-protocol.md](research-protocol.md).
No empirical improvement, production assurance, or novelty conclusion is claimed.
