import { describe, expect, it } from "vitest";

import {
  closeMcpLifecycleV1,
  gatewayScaffoldStatus,
  initialMcpLifecycleStateV1,
  initializeRequestV1Schema,
  initializeResponseV1Schema,
  initializedNotificationV1Schema,
  mcpLifecycleStateV1Schema,
  pingRequestV1Schema,
  selectedMcpProtocolVersionV1,
  transitionMcpLifecycleV1
} from "../../src/index.js";

const initializeRequest = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {
      roots: { listChanged: true },
      sampling: {},
      elicitation: {}
    },
    clientInfo: {
      name: "disposable-test-client",
      title: "Disposable Test Client",
      version: "1.0.0"
    }
  }
} as const;

const initializedNotification = {
  jsonrpc: "2.0",
  method: "notifications/initialized"
} as const;

describe("MCP 2025-06-18 initialization contracts", () => {
  it("accepts the protocol initialize request and initialized notification shapes", () => {
    expect(initializeRequestV1Schema.parse(initializeRequest)).toEqual(initializeRequest);
    expect(initializedNotificationV1Schema.parse(initializedNotification)).toEqual(
      initializedNotification
    );
  });

  it("accepts bounded additional client capabilities without negotiating them", () => {
    const request = {
      ...initializeRequest,
      params: {
        ...initializeRequest.params,
        capabilities: {
          ...initializeRequest.params.capabilities,
          "example.extension": { enabled: true }
        }
      }
    } as const;
    const transition = transitionMcpLifecycleV1(initialMcpLifecycleStateV1, request);

    expect(transition.state.declaredClientCapabilities).toContain("example.extension");
    expect(transition.state.unrecognizedClientCapabilities).toEqual([
      "example.extension"
    ]);
    expect(transition.state.serverCapabilities).toEqual({});
  });

  it("rejects malformed JSON and dangerous capability keys before normalization", () => {
    const capabilities = JSON.parse('{"__proto__":{"enabled":true}}') as object;
    expect(
      initializeRequestV1Schema.safeParse({
        ...initializeRequest,
        params: { ...initializeRequest.params, capabilities }
      }).success
    ).toBe(false);
    expect(
      initializeRequestV1Schema.safeParse({ ...initializeRequest, jsonrpc: "1.0" }).success
    ).toBe(false);
  });
});

describe("non-forwarding MCP lifecycle state machine", () => {
  it("performs initialize then initialized in the required order", () => {
    const initialized = transitionMcpLifecycleV1(
      initialMcpLifecycleStateV1,
      initializeRequest
    );
    expect(initialized.state).toMatchObject({
      phase: "INITIALIZE_RESPONSE_SENT",
      requestedProtocolVersion: "2025-06-18",
      negotiatedProtocolVersion: selectedMcpProtocolVersionV1,
      protectedForwardingEnabled: false
    });
    expect(initializeResponseV1Schema.parse(initialized.response)).toMatchObject({
      id: initializeRequest.id,
      result: {
        protocolVersion: selectedMcpProtocolVersionV1,
        capabilities: {}
      }
    });

    const ready = transitionMcpLifecycleV1(
      initialized.state,
      initializedNotification
    );
    expect(ready.response).toBeNull();
    expect(ready.state.phase).toBe("READY_NON_FORWARDING");
  });

  it("returns the supported version when the client requests another revision", () => {
    const transition = transitionMcpLifecycleV1(initialMcpLifecycleStateV1, {
      ...initializeRequest,
      params: { ...initializeRequest.params, protocolVersion: "2026-01-01" }
    });

    expect(transition.state.requestedProtocolVersion).toBe("2026-01-01");
    expect(transition.response).toMatchObject({
      result: { protocolVersion: "2025-06-18" }
    });
  });

  it("advertises registry-backed discovery without enabling protected forwarding", () => {
    const transition = transitionMcpLifecycleV1(
      initialMcpLifecycleStateV1,
      initializeRequest,
      { discoveryEnabled: true }
    );

    expect(transition.state.serverCapabilities).toEqual({
      tools: { listChanged: false }
    });
    expect(transition.state.protectedForwardingEnabled).toBe(false);
    expect(transition.response).toMatchObject({
      result: { capabilities: { tools: { listChanged: false } } }
    });
  });

  it("allows ping but denies operational requests before initialization", () => {
    const ping = { jsonrpc: "2.0", id: "ping-001", method: "ping" } as const;
    expect(pingRequestV1Schema.safeParse(ping).success).toBe(true);
    expect(
      transitionMcpLifecycleV1(initialMcpLifecycleStateV1, ping).response
    ).toEqual({ jsonrpc: "2.0", id: "ping-001", result: {} });

    const operation = transitionMcpLifecycleV1(initialMcpLifecycleStateV1, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list"
    });
    expect(operation.state.phase).toBe("NEW");
    expect(operation.response).toMatchObject({ error: { code: -32002 } });
  });

  it("does not answer an out-of-order initialized notification", () => {
    const transition = transitionMcpLifecycleV1(
      initialMcpLifecycleStateV1,
      initializedNotification
    );
    expect(transition.state.phase).toBe("NEW");
    expect(transition.response).toBeNull();
  });

  it("requires the initialized notification before operational requests", () => {
    const initialized = transitionMcpLifecycleV1(
      initialMcpLifecycleStateV1,
      initializeRequest
    );
    const operation = transitionMcpLifecycleV1(initialized.state, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list"
    });
    expect(operation.state.phase).toBe("INITIALIZE_RESPONSE_SENT");
    expect(operation.response).toMatchObject({ error: { code: -32002 } });
  });

  it("rejects duplicate initialization without changing negotiated state", () => {
    const initialized = transitionMcpLifecycleV1(
      initialMcpLifecycleStateV1,
      initializeRequest
    );
    const ready = transitionMcpLifecycleV1(
      initialized.state,
      initializedNotification
    );
    const duplicate = transitionMcpLifecycleV1(ready.state, initializeRequest);

    expect(duplicate.state).toEqual(ready.state);
    expect(duplicate.response).toMatchObject({ error: { code: -32600 } });
  });

  it("advertises no operational capability and fails closed after readiness", () => {
    const initialized = transitionMcpLifecycleV1(
      initialMcpLifecycleStateV1,
      initializeRequest
    );
    const ready = transitionMcpLifecycleV1(
      initialized.state,
      initializedNotification
    );
    const toolsList = transitionMcpLifecycleV1(ready.state, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/list"
    });

    expect(ready.state.serverCapabilities).toEqual({});
    expect(toolsList.response).toMatchObject({
      error: {
        code: -32601,
        data: { method: "tools/list", coverage: "UNPROTECTED" }
      }
    });
    expect(toolsList.state.protectedForwardingEnabled).toBe(false);
  });

  it("closes transport state without leaving a negotiated version active", () => {
    const initialized = transitionMcpLifecycleV1(
      initialMcpLifecycleStateV1,
      initializeRequest
    );
    const closed = closeMcpLifecycleV1(initialized.state);

    expect(mcpLifecycleStateV1Schema.parse(closed)).toMatchObject({
      phase: "CLOSED",
      initializeRequestId: null,
      negotiatedProtocolVersion: null,
      protectedForwardingEnabled: false
    });
    expect(
      transitionMcpLifecycleV1(closed, {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/list"
      }).response
    ).toMatchObject({ error: { code: -32000 } });
  });

  it("does not change the repository-level non-forwarding posture", () => {
    expect(gatewayScaffoldStatus).toEqual({
      phase: "phase-2-mcp-gateway",
      implementation: "non-forwarding-discovery-adapter",
      coverage: "UNPROTECTED",
      acceptsLifecycleTraffic: true,
      protectedForwardingEnabled: false
    });
  });
});
