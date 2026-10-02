"""Reproducible, limited exact-phrase screening against two local source papers.

This is not a plagiarism detector or a similarity percentage. Reference lists,
LaTeX commands and fenced Markdown examples are excluded from draft prose.
"""
from pathlib import Path
import hashlib
import json
import re
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
WINDOW = 12


def words(text):
    return re.findall(r"[a-z0-9]+", text.lower())


def prose(path):
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".tex":
        text = text.split(r"\bibliographystyle")[0]
        text = re.sub(r"(?m)%.*$", "", text)
        text = re.sub(r"\\(?:cite|ref|label|includegraphics|url|href)(?:\[[^\]]*\])?\{[^}]*\}", " ", text)
        text = re.sub(r"\\[A-Za-z]+\*?(?:\[[^\]]*\])?", " ", text)
    else:
        text = re.sub(r"```[\s\S]*?```", " ", text)
        text = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", text)
        text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return words(text)


def grams(tokens):
    return {tuple(tokens[i:i + WINDOW]) for i in range(len(tokens) - WINDOW + 1)}


source_paths = [ROOT / "docs/Security of AI Agents.pdf",
                ROOT / "docs/Agentic_AI_Security_Threats_Defenses_Evaluation_and_Open_Challenges.pdf"]
source_data = []
for path in source_paths:
    tokens = words("\n".join(page.extract_text() or "" for page in PdfReader(path).pages))
    source_data.append((path, tokens, grams(tokens)))

results = []
for relative in ["report.md", "paper/main.tex"]:
    path = ROOT / relative
    tokens = prose(path)
    draft_grams = grams(tokens)
    checks = []
    for source, source_tokens, source_grams in source_data:
        overlap = sorted(draft_grams & source_grams)
        checks.append({"source": source.relative_to(ROOT).as_posix(),
                       "sourceSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                       "extractedSourceTokens": len(source_tokens),
                       "matchingDistinct12TokenWindows": len(overlap),
                       "sampleMatchedWindows": [" ".join(g) for g in overlap[:3]]})
    results.append({"document": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "screenedTokens": len(tokens), "checks": checks})

output = {"schemaVersion": "1.0.0", "method": "EXACT_12_TOKEN_LOCAL_SOURCE_SCREEN",
          "date": "2026-10-01", "documents": results,
          "limits": ["Only two supplied source PDFs are screened; this is not a full database search.",
                     "PDF extraction, tokenization and markup removal can miss matches.",
                     "Paraphrases, translations, ideas, images and unpublished submissions are not detected.",
                     "An overlap requires attribution review; no overlap cannot establish originality.",
                     "No proprietary similarity score, plagiarism-free certificate or AI detector result is produced."]}
target = ROOT / "report-assets/originality-local-audit.json"
target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"output": target.relative_to(ROOT).as_posix(),
                  "documents": [{"document": r["document"],
                                  "matchingWindowsBySource": [c["matchingDistinct12TokenWindows"] for c in r["checks"]]}
                                 for r in results]}))
