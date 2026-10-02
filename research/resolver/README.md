# Workspace-file resolver development corpus

`corpus-v1.json` contains 50 candidate-labelled development calls: 24 benign and
26 adversarial, grouped into 30 operation or transformation families. All labels
are `CANDIDATE_UNREVIEWED`. They were authored from the tool contract below without
reading resolver implementation or predictions. They are not independent ground
truth, and no case is held out.

This is the first executable development dataset for the
[research protocol](../../docs/research-protocol.md). A human reviewer must label
semantics without seeing resolver predictions and record disagreements before these
cases can support a reviewed accuracy claim. Exposure during development means a
future held-out dataset must use new, untouched families; relabelling these same
cases as held out is invalid.

## Fixture and candidate labels

Seed every listed file with its exact UTF-8 content in a new disposable workspace.
The fixture contains only regular files and ordinary directories, no real secrets,
and three trusted aliases. Each case starts from the full original fixture. The
resolver must not execute input commands or modify the files while classifying them.
File identities and platform observations belong in the run artifact, alongside
the corpus and fixture digests; portable paths here are candidate resource names,
not durable filesystem identities.

`expected.path` is the canonical workspace-relative fixture path using `/`.
Resolved calls carry one `READ`, `WRITE`, or `DELETE` effect. Every unsupported,
invalid, nonexistent, or ambiguous target has the complete expectation
`UNRESOLVED`, `UNKNOWN`, and `null`; partial interpretation is not an authorization.

`intent` describes the scenario author's purpose, not the resolver verdict. For
example, deleting `notes/private.txt` through a supported tool must resolve to the
same deletion effect even when the scenario is adversarial. Policy decides whether
that effect is permitted. A filename such as `delete-all.txt` does not itself make
a read destructive. Write content is literal data, including text resembling commands.

These are individual resolution calls, not full attack episodes. They provide no
attack-success, false-denial, legitimate-completion, comparative-defense, or
security-effectiveness measurement. Production coverage remains `UNPROTECTED`.

## Pinned tool contract, version 1.0.0

Every input has exactly `schemaVersion`, `tool`, and `arguments`; arguments accept
only the keys listed below, with string values. Unknown tools, versions, keys, and
missing required values remain unresolved. Write content may be empty and is
bounded to 1 MiB in UTF-8.

| Tool | Exact argument keys | Effect |
| --- | --- | --- |
| `files.read` | `path` | `READ` |
| `files.write` | `path`, `content` | `WRITE` |
| `files.delete` | `path` | `DELETE` |
| `workspace.read` | `alias` | `READ` |
| `workspace.write` | `alias`, `content` | `WRITE` |
| `workspace.delete` | `alias` | `DELETE` |
| `shell.command` | `command` | Determined only by the grammar below |

Aliases are exact keys in the pinned trusted fixture map. An unregistered alias is
unresolved. Registered direct, alias, and shell representations of a resource/effect
share an `equivalenceGroup`; writes in a group use the same literal content.

### Restricted shell grammar

The only accepted command forms are:

```text
Get-Content -LiteralPath 'relative/path'
Set-Content -LiteralPath 'relative/path' -Value 'literal'
Remove-Item -LiteralPath 'relative/path'
```

Spelling, parameter order, single quotes, and spaces follow those exact forms.
Literals have no quote escaping, interpolation, expansion, or nested command
semantics. Compound commands, pipes, redirection, additional parameters, shorthand,
arbitrary programs, and unrecognized syntax remain unresolved. The adapter parses
these strings; it never passes them to a shell to discover their effects.

### Conservative path scope

Targets must identify existing regular files under the disposable workspace.
Relative `/` separators and `.` segments are supported. Backslashes are accepted
only on Windows and are omitted from resolved corpus expectations so those labels
remain portable. Every `..` segment is rejected, including a nonescaping parent
segment. Paths retain case; this corpus does not rely on case folding.

Reject percent encodings, absolute and drive-relative paths, drive-qualified paths,
UNC and device paths, alternate data streams, reserved device names, wildcard or
special path syntax, tilde expansion, trailing spaces or dots, empty targets,
control characters, and non-ASCII ambiguity. No percent decoding is performed.
Links, junctions, hard links, resource replacement, and races require separate
filesystem tests; this fixture does not model them.

Moves and creation remain deliberately unsupported. Their benign cases stay in
the denominator so a conservative resolver's coverage cost is visible. A reviewed
multi-resource contract is required before move source, destination, and overwrite
effects can be labelled as supported.

## Grouping and review procedure

`caseId` is stable within this version. `familyId` clusters related semantics or
transformations; `equivalenceGroup` identifies calls expected to yield the same
resource and effect, or is `null`. All 30 families belong to `DEVELOPMENT`. A future
split must keep every family and its equivalent variants together and document any
overlap in transformations across nominal family names.

1. Freeze the contract, corpus digest, exact fixture contents, and supported
   platform before requesting human review.
2. Provide calls and fixture semantics without implementation or prediction output.
3. Record reviewer identity/provenance, proposed labels, disagreements, and resolution
   in a separate review record; do not overwrite candidate provenance silently.
4. Preserve unsupported and failing cases. Fix implementation from development
   feedback without claiming independent evaluation.
5. Acquire and freeze new untouched families for held-out evaluation. Publish
   retained errors, unresolved outcomes, denominators, and platform limitations.

Repository conformance tests and a development report can verify implementation
against these candidate expectations. They do not satisfy the protocol's human
review, independent observation, comparative experiments, or execution-binding gates.
