import { describe, expect, it } from "vitest";

import { gatewayScaffoldStatus } from "../../src/index.js";

describe("gateway security posture", () => {
  it("reports lifecycle-only traffic without claiming protected forwarding", () => {
    expect(gatewayScaffoldStatus.phase).toBe("phase-2-mcp-gateway");
    expect(gatewayScaffoldStatus.coverage).toBe("UNPROTECTED");
    expect(gatewayScaffoldStatus.acceptsLifecycleTraffic).toBe(true);
    expect(gatewayScaffoldStatus.protectedForwardingEnabled).toBe(false);
  });
});
