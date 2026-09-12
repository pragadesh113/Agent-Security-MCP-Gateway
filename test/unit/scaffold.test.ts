import { describe, expect, it } from "vitest";

import { gatewayScaffoldStatus } from "../../src/index.js";

describe("Phase 2 scaffold", () => {
  it("does not claim enforcement before the gateway exists", () => {
    expect(gatewayScaffoldStatus).toEqual({
      phase: "phase-2-mcp-gateway",
      implementation: "non-forwarding-discovery-adapter",
      coverage: "UNPROTECTED",
      acceptsLifecycleTraffic: true,
      protectedForwardingEnabled: false
    });
  });
});
