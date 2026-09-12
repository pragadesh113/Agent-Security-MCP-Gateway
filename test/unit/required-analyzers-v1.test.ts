import { describe, expect, it } from "vitest";

import {
  RequiredAnalyzerConfigurationErrorV1,
  RequiredAnalyzerRegistryV1,
  createCompleteRequiredAnalyzerRegistryV1,
  requiredAnalyzerCategoriesV1,
  type RequiredAnalyzerCategoryV1,
  type RequiredAnalyzerRequestV1,
  type RequiredAnalyzerV1
} from "../../src/action-normalizer/required-analyzers-v1.js";

function request(category: RequiredAnalyzerCategoryV1): RequiredAnalyzerRequestV1 {
  return { schemaVersion: "1.0.0", category, operation: "inspect", syntax: "json", syntaxVersion: "1", input: {} };
}

function analyzer(category: RequiredAnalyzerCategoryV1, result?: unknown): RequiredAnalyzerV1 {
  return {
    category, supportedOperations: ["inspect"], supportedSyntaxes: { json: ["1"] },
    analyze: (value) => result ?? ({
      schemaVersion: "1.0.0", analyzerId: `${category.toLowerCase()}-analyzer`, analyzerVersion: "1",
      category, operation: value.operation, syntax: value.syntax, syntaxVersion: value.syntaxVersion,
      status: "RESOLVED", complete: true, ambiguous: false, effect: "READ",
      resources: [{ resourceId: `${category.toLowerCase()}-resource`, canonicalReference: "canonical:resource" }],
      evidence: ["syntax-and-operation-resolved"]
    })
  };
}

describe("required analyzer registry v1", () => {
  it("dispatches to a dedicated analyzer for every required category", async () => {
    const calls: string[] = [];
    const entries = Object.fromEntries(requiredAnalyzerCategoriesV1.map((category) => [category, {
      ...analyzer(category), analyze: (value: RequiredAnalyzerRequestV1) => {
        calls.push(category); return analyzer(category).analyze(value);
      }
    }])) as Record<RequiredAnalyzerCategoryV1, RequiredAnalyzerV1>;
    const registry = new RequiredAnalyzerRegistryV1(entries);
    for (const category of requiredAnalyzerCategoriesV1) {
      expect((await registry.analyze(request(category))).status).toBe("RESOLVED");
    }
    expect(calls).toEqual(requiredAnalyzerCategoriesV1);
  });

  it("quarantines missing analyzers and unknown operations, syntaxes, and versions", async () => {
    const registry = new RequiredAnalyzerRegistryV1({ FILESYSTEM: analyzer("FILESYSTEM") });
    expect(await registry.analyze(request("SHELL"))).toMatchObject({ status: "QUARANTINED", reason: "MISSING_ANALYZER", effect: "UNKNOWN" });
    expect(await registry.analyze({ ...request("FILESYSTEM"), operation: "invented" })).toMatchObject({ reason: "UNKNOWN_OPERATION" });
    expect(await registry.analyze({ ...request("FILESYSTEM"), syntax: "invented" })).toMatchObject({ reason: "UNKNOWN_SYNTAX" });
    expect(await registry.analyze({ ...request("FILESYSTEM"), syntaxVersion: "999" })).toMatchObject({ reason: "UNKNOWN_VERSION" });
  });

  it.each([
    ["throw", { analyze: () => { throw new Error("failed"); } }, "ANALYZER_FAILURE"],
    ["invalid", { analyze: () => ({ safe: true }) }, "INVALID_RESULT"],
    ["partial", { analyze: () => ({ status: "PARTIAL", complete: false }) }, "PARTIAL_RESULT"]
  ] as const)("quarantines %s analyzer output", async (_name, override, reason) => {
    const registry = new RequiredAnalyzerRegistryV1({ FILESYSTEM: { ...analyzer("FILESYSTEM"), ...override } });
    expect(await registry.analyze(request("FILESYSTEM"))).toEqual(expect.objectContaining({
      status: "QUARANTINED", complete: false, ambiguous: true, effect: "UNKNOWN", reason,
      resources: [{ resourceId: "unresolved", canonicalReference: "unresolved" }]
    }));
  });

  it("rejects authority substitution and never infers safety from malformed input", async () => {
    const registry = new RequiredAnalyzerRegistryV1({
      FILESYSTEM: analyzer("FILESYSTEM", {
        schemaVersion: "1.0.0", analyzerId: "forged", analyzerVersion: "1", category: "SHELL",
        operation: "inspect", syntax: "json", syntaxVersion: "1", status: "RESOLVED",
        complete: true, ambiguous: false, effect: "READ",
        resources: [{ resourceId: "resource", canonicalReference: "canonical:resource" }], evidence: ["claim"]
      })
    });
    expect(await registry.analyze(request("FILESYSTEM"))).toMatchObject({ status: "QUARANTINED", reason: "INVALID_RESULT" });
    expect(await registry.analyze({ category: "FILESYSTEM", operation: "inspect", input: { safe: true } }))
      .toMatchObject({ status: "QUARANTINED", effect: "UNKNOWN", ambiguous: true });
  });

  it.each([
    ["category", { category: "SHELL" }],
    ["blank operation", { supportedOperations: [" "] }],
    ["duplicate operation", { supportedOperations: ["inspect", "inspect"] }],
    ["blank syntax", { supportedSyntaxes: { " ": ["1"] } }],
    ["no syntax versions", { supportedSyntaxes: { json: [] } }],
    ["blank syntax version", { supportedSyntaxes: { json: [" "] } }],
    ["duplicate syntax version", { supportedSyntaxes: { json: ["1", "1"] } }]
  ] as const)("rejects invalid analyzer configuration: %s", (_name, override) => {
    expect(() => new RequiredAnalyzerRegistryV1({
      FILESYSTEM: { ...analyzer("FILESYSTEM"), ...override }
    })).toThrow(RequiredAnalyzerConfigurationErrorV1);
  });

  it("refuses production activation until all required categories are configured", async () => {
    expect(() => createCompleteRequiredAnalyzerRegistryV1({ FILESYSTEM: analyzer("FILESYSTEM") }))
      .toThrow(RequiredAnalyzerConfigurationErrorV1);
    const complete = Object.fromEntries(requiredAnalyzerCategoriesV1.map((category) =>
      [category, analyzer(category)])) as Record<RequiredAnalyzerCategoryV1, RequiredAnalyzerV1>;
    const registry = createCompleteRequiredAnalyzerRegistryV1(complete);
    expect((await registry.analyze(request("SCHEMA"))).status).toBe("RESOLVED");
  });
});
