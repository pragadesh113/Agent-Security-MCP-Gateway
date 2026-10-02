# Research protocol: equivalent effects and exact approval

**Version:** 0.1, 2026-09-27 | **Status:** protocol prepared; study not run or frozen  
**Plan:** [research extension, section 1](addon-md.txt)  
**Baseline:** `a887ce725d3659cef386cf4e0705fc5e0b37fcca`; later working-tree changes must
be captured in the experiment manifest. This document does not change runtime policy.

## 1. Contribution and questions

**Hypothesis:** for supported MCP operations, authorization based on resolved effects
reduces bypasses through equivalent tool representations while preserving legitimate
completion and binding each approval to one execution.

The candidate contribution is an independently evaluated resource/effect resolver,
paired security and utility evidence, and systematic evidence for approval binding
under resource substitution and execution failure. A gateway architecture alone does
not establish novelty. [Progent v3](https://arxiv.org/html/2504.11703v3) already provides
deterministic privilege enforcement and approval of policy expansion;
[MCIP v7](https://arxiv.org/html/2505.14590v7) models contextual information flows and
evaluates a learned Guardian. See the [comparison matrix](research-related-work.md).

| Question | Observation that answers it |
| --- | --- |
| RQ1: Are equivalent effects resolved correctly? | Independently labelled resource/effect predictions, errors, and unresolved cases |
| RQ2: Does canonicalization improve security and utility? | Paired prohibited-effect and benign-completion outcomes against baselines and ablations |
| RQ3: Does approval remain bound through change and failure? | Downstream requests/effects correlated with consumption, recovery, and fault points |

## 2. Scope, adversary, and assumptions

Start with regular-file read, write, move, and deletion in a disposable Windows
workspace, through registered file tools, workspace aliases, and a restricted shell
adapter. Pin tool schemas, shell grammar, working directory, filesystem semantics,
alias map, and resource-state versions before labelling cases. Accept only explicitly
specified command forms; compound commands, expansion, arbitrary programs, and unknown
syntax remain unresolved. Never run an unparsed command to discover its meaning.

Record source and destination roles for moves, including overwrite effects. The
current single-effect contract needs a reviewed representation before a move can be
declared supported. Unsupported moves remain in the coverage denominator. Percent
decoding, case folding, links, junctions, traversal, and malformed paths require cases
grounded in actual tool and filesystem semantics; lexical normalization is insufficient.

The attacker knows the defense and may alter arguments, tool descriptions, returned
content, aliases, representations, call ordering, retries, and concurrent requests.
It may attempt unauthorized changes or disclosure to an instrumented disposable sink.
It does not control gateway code, policy administration, PostgreSQL, or the independent
observer. Native/direct bypass attempts test isolation separately. Coverage remains
`UNPROTECTED` unless an exact disposable scope has independently verified controls;
production forwarding remains disabled. Trust stays in shadow mode; the supervisor
is disabled for the principal comparison. No production resources or human-subject
claims are included.

Registered fixture tool contracts and implementations must agree on executed effects;
metadata may be hostile, but compromised tool code, kernel, and filesystem are outside
this pilot's guarantee. Result validation alone cannot prevent a server's hidden effects.

## 3. Corpus and independent ground truth

Each case records a stable ID, operation and transformation families, equivalence
group, tool/schema version, arguments, initial fixture digest, platform, policy intent,
expected resource identities/effects, permitted destinations, and label provenance.
Keep read, modify, move, delete, disclosure, and unresolved outcomes distinct.

Prepare approximately 20 benign tasks and 20 attack scenarios for development/pilot.
A human reviewer labels expected semantics without resolver predictions; a separate
observer captures file identities, before/after state, downstream requests, and sink
receipts where safe execution is appropriate. Reconcile disagreements explicitly.
Until reviewed, author-produced cases are **candidate labels**, not ground truth.

Assign entire operation or transformation families, including every equivalent variant,
to development or held-out partitions. Freeze the split before evaluating held-out
cases; retain failures, unsupported cases, and inconclusive observations. If held-out
feedback changes the resolver, label those cases development and obtain a fresh
held-out set. Do not reuse existing injected-resolver expectations as independent labels.

## 4. Comparative experiment and measurements

Run matched tasks, initial states, authorization intent, model settings, seeds, and
budgets under six conditions: native MCP; tool-name/argument policy; a pinned
reproducible prior defense (Progent first candidate); full gateway; gateway without
effect canonicalization; gateway without result governance. Define what each ablation
retains. Use identical policy intent, approval oracle, and permitted resources wherever
possible. Log unavoidable differences and failed reproduction attempts. A substitute
implementation must be identified as such. Weaker conditions use disposable isolation.

| Measure | Numerator / denominator or unit |
| --- | --- |
| Attack success | Episodes with any observed prohibited effect / attacked episodes |
| Legitimate completion | Benign episodes completed within policy / benign episodes |
| False denial | Incorrectly denied independently permitted operations / permitted operations |
| Resolver correctness | Correct resource identity and effect, separately / labelled cases |
| Unsafe interpretation | Predictions that could authorize a prohibited effect / labelled cases |
| Unresolved rate | Unresolved cases / cases, also reported within supported scope |
| Approval burden | Requests and repeated requests per task |
| Overhead | Measured gateway processing time; human waiting excluded |

Also report policy consistency within equivalence groups, leakage, call amplification,
timeouts, recovery outcomes, and latency p50/p95. Preserve counts and denominators;
missing observations are inconclusive, never safe by default. Treat task families as
clusters, pair conditions on the same tasks, and compute uncertainty intervals by
resampling whole families. Pilot variability determines main-study size, repetitions,
minimum useful improvement, and acceptable utility loss; freeze these before main runs.
A scripted approval oracle measures mechanism behavior, not human judgment or fatigue.

## 5. Execution binding, artifacts, and decision gates

Systematically exercise changed arguments, identity, route, schema, policy, and alias
target; expiry during dispatch; concurrent consumers; database/downstream loss; and
crashes before/after consumption, during forwarding, and after effects but before
outcome persistence. Record both durable state and observed effects. Require at most
one dispatch per approval, no substituted effect, and explicit ambiguity with no
automatic retry. Fresh resolution must precede consumption; document residual races
and any handle/version/conditional-operation guarantee. Bounded exploration reports
its state bounds and cannot establish universal correctness.

Retain code/configuration digests, corpus and split manifests, dependency versions,
models, seeds, budgets, observations, exclusions, fault schedules, and analysis commands.
Existing conformance tests establish local behavior; they do not answer RQ1–RQ3 as a
comparative study. The current canonicalizer accepts injected semantic resolvers,
and the approved-call loader reloads stored authority rather than independently
resolving current filesystem meaning.

**Gates:** resolve unsafe development classifications before freezing the resolver;
complete the closest-work reproduction assessment before costly main experiments;
freeze metrics and analysis after the pilot; retain negative held-out results. If
novelty or useful security/utility improvement is unsupported, narrow the contribution
and report that outcome. This protocol completes one planning deliverable only.

**Next action:** construct the versioned candidate resolver corpus, tool/grammar scope,
and family split; obtain independent label review before treating it as evaluation data.
