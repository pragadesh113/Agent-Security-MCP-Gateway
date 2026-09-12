import { describe, expect, it } from "vitest";

import {
  closeMcpLifecycleV1,
  initialMcpLifecycleStateV1,
  initializeRequestV1Schema,
  initializedNotificationV1Schema,
  transitionMcpLifecycleV1
} from "../../src/index.js";

const initializeRequest = {
  jsonrpc: "2.0",
  id: "initialize-adversarial-001",
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: {
      name: "adversarial-test-client",
      version: "1.0.0"
    }
  }
} as const;

const initializedNotification = {
  jsonrpc: "2.0",
  method: "notifications/initialized"
} as const;

function initialize() {
  return transitionMcpLifecycleV1(initialMcpLifecycleStateV1, initializeRequest);
}

function ready() {
  const initialized = initialize();
  return transitionMcpLifecycleV1(initialized.state, initializedNotification);
}

function nestedObject(depth: number): Record<string, unknown> {
  let value: Record<string, unknown> = {};
  for (let index = 0; index < depth; index += 1) {
    value = { nested: value };
  }
  return value;
}

describe("adversarial initialize capability validation", () => {
  it.each([null, [], "roots", 1, true])(
    "rejects a non-object capability collection: %j",
    (capabilities) => {
      expect(
        initializeRequestV1Schema.safeParse({
          ...initializeRequest,
          params: { ...initializeRequest.params, capabilities }
        }).success
      ).toBe(false);
    }
  );

  it("rejects capability values that are not objects", () => {
    for (const capability of [null, [], "enabled", 1, true]) {
      expect(
        initializeRequestV1Schema.safeParse({
          ...initializeRequest,
          params: {
            ...initializeRequest.params,
            capabilities: { "vendor.extension": capability }
          }
        }).success
      ).toBe(false);
    }
  });

  it("rejects deeply nested capability data", () => {
    expect(
      initializeRequestV1Schema.safeParse({
        ...initializeRequest,
        params: {
          ...initializeRequest.params,
          capabilities: { "vendor.deep": nestedObject(34) }
        }
      }).success
    ).toBe(false);
  });

  it("rejects capability data that exceeds the JSON node bound", () => {
    expect(
      initializeRequestV1Schema.safeParse({
        ...initializeRequest,
        params: {
          ...initializeRequest.params,
          capabilities: {
            "vendor.wide": { entries: Array.from({ length: 4_096 }, () => null) }
          }
        }
      }).success
    ).toBe(false);
  });

  it("rejects capability data that exceeds the aggregate string bound", () => {
    expect(
      initializeRequestV1Schema.safeParse({
        ...initializeRequest,
        params: {
          ...initializeRequest.params,
          capabilities: { "vendor.large": { value: "x".repeat(1_048_577) } }
        }
      }).success
    ).toBe(false);
  });

  it.each(["__proto__", "constructor", "prototype"])(
    "rejects a nested prototype-affecting key: %s",
    (dangerousKey) => {
      const extension = JSON.parse(
        `{"safe":{"${dangerousKey}":{"polluted":true}}}`
      ) as Record<string, unknown>;

      expect(
        initializeRequestV1Schema.safeParse({
          ...initializeRequest,
          params: {
            ...initializeRequest.params,
            capabilities: { "vendor.prototype": extension }
          }
        }).success
      ).toBe(false);
      expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
    }
  );

  it("rejects more capability declarations than lifecycle state can record", () => {
    const capabilities = Object.fromEntries(
      Array.from({ length: 129 }, (_, index) => [
        `vendor.extension.${String(index)}`,
        {}
      ])
    );

    expect(
      initializeRequestV1Schema.safeParse({
        ...initializeRequest,
        params: { ...initializeRequest.params, capabilities }
      }).success
    ).toBe(false);
  });

  it("records unknown capabilities as unrecognized without advertising them", () => {
    const transition = transitionMcpLifecycleV1(initialMcpLifecycleStateV1, {
      ...initializeRequest,
      params: {
        ...initializeRequest.params,
        capabilities: {
          sampling: {},
          "z.vendor.extension": { enabled: true },
          "a.vendor.extension": { nested: { mode: "test" } }
        }
      }
    });

    expect(transition.state.declaredClientCapabilities).toEqual([
      "a.vendor.extension",
      "sampling",
      "z.vendor.extension"
    ]);
    expect(transition.state.unrecognizedClientCapabilities).toEqual([
      "a.vendor.extension",
      "z.vendor.extension"
    ]);
    expect(transition.state.serverCapabilities).toEqual({});
    expect(transition.response).toMatchObject({ result: { capabilities: {} } });
  });
});

describe("adversarial lifecycle ordering and notification behavior", () => {
  it("rejects duplicate initialize while acknowledgement is pending", () => {
    const first = initialize();
    const duplicate = transitionMcpLifecycleV1(first.state, {
      ...initializeRequest,
      id: "initialize-adversarial-duplicate"
    });

    expect(duplicate.state).toEqual(first.state);
    expect(duplicate.response).toMatchObject({
      id: "initialize-adversarial-duplicate",
      error: { code: -32002 }
    });
  });

  it("rejects duplicate initialize after readiness without changing state", () => {
    const current = ready();
    const duplicate = transitionMcpLifecycleV1(current.state, {
      ...initializeRequest,
      id: "initialize-adversarial-ready-duplicate"
    });

    expect(duplicate.state).toEqual(current.state);
    expect(duplicate.response).toMatchObject({
      id: "initialize-adversarial-ready-duplicate",
      error: { code: -32600 }
    });
  });

  it("silently ignores initialized before initialize and duplicate initialized", () => {
    const outOfOrder = transitionMcpLifecycleV1(
      initialMcpLifecycleStateV1,
      initializedNotification
    );
    expect(outOfOrder.state).toEqual(initialMcpLifecycleStateV1);
    expect(outOfOrder.response).toBeNull();

    const current = ready();
    const duplicate = transitionMcpLifecycleV1(
      current.state,
      initializedNotification
    );
    expect(duplicate.state).toEqual(current.state);
    expect(duplicate.response).toBeNull();
  });

  it("never returns a response to well-formed notifications in any phase", () => {
    const notification = {
      jsonrpc: "2.0",
      method: "notifications/vendor-event",
      params: { untrusted: true }
    } as const;
    const initialized = initialize();
    const current = ready();
    const closed = closeMcpLifecycleV1(current.state);

    for (const state of [
      initialMcpLifecycleStateV1,
      initialized.state,
      current.state,
      closed
    ]) {
      const transition = transitionMcpLifecycleV1(state, notification);
      expect(transition.state).toEqual(state);
      expect(transition.response).toBeNull();
    }
  });

  it("does not interpret an initialized notification carrying an id as an acknowledgement", () => {
    const initialized = initialize();
    const requestShapedAcknowledgement = transitionMcpLifecycleV1(initialized.state, {
      ...initializedNotification,
      id: "not-a-notification"
    });

    expect(requestShapedAcknowledgement.state.phase).toBe(
      "INITIALIZE_RESPONSE_SENT"
    );
    expect(requestShapedAcknowledgement.response).toMatchObject({
      id: "not-a-notification",
      error: { code: -32002 }
    });
  });

  it("rejects initialized notification fields outside its protocol shape", () => {
    expect(
      initializedNotificationV1Schema.safeParse({
        ...initializedNotification,
        result: {}
      }).success
    ).toBe(false);
  });
});

describe("adversarial JSON-RPC request IDs", () => {
  it.each([
    -Number.MAX_SAFE_INTEGER,
    0,
    Number.MAX_SAFE_INTEGER,
    "request-id",
    "x".repeat(128)
  ])("preserves a valid edge request id: %j", (id) => {
    const transition = transitionMcpLifecycleV1(initialMcpLifecycleStateV1, {
      ...initializeRequest,
      id
    });

    expect(transition.state.initializeRequestId).toBe(id);
    expect(transition.response).toMatchObject({ id });
  });

  it.each([
    null,
    "",
    "x".repeat(129),
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    {},
    []
  ])("rejects an invalid initialize request id: %j", (id) => {
    expect(
      initializeRequestV1Schema.safeParse({ ...initializeRequest, id }).success
    ).toBe(false);

    const transition = transitionMcpLifecycleV1(initialMcpLifecycleStateV1, {
      ...initializeRequest,
      id
    });
    expect(transition.state).toEqual(initialMcpLifecycleStateV1);
    expect(transition.response).toMatchObject({
      id: null,
      error: { code: -32600 }
    });
  });
});

describe("closed and permanently non-forwarding lifecycle behavior", () => {
  it("keeps a closed session closed for requests, notifications, and malformed input", () => {
    const closed = closeMcpLifecycleV1(ready().state);
    const inputs = [
      { jsonrpc: "2.0", id: 41, method: "ping" },
      { jsonrpc: "2.0", id: 42, method: "initialize", params: initializeRequest.params },
      { jsonrpc: "2.0", id: 43, method: "tools/list" },
      { jsonrpc: "2.0", id: 44, method: "tools/call", params: { name: "anything" } },
      null
    ];

    for (const input of inputs) {
      const transition = transitionMcpLifecycleV1(closed, input);
      expect(transition.state).toEqual(closed);
      expect(transition.response).toMatchObject({ error: { code: -32000 } });
    }

    const notification = transitionMcpLifecycleV1(closed, {
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId: 43 }
    });
    expect(notification.state).toEqual(closed);
    expect(notification.response).toBeNull();
  });

  it.each(["tools/list", "tools/call"])(
    "never makes %s available before, during, or after initialization",
    (method) => {
      const initialized = initialize();
      const current = ready();
      const closed = closeMcpLifecycleV1(current.state);
      const phases = [
        initialMcpLifecycleStateV1,
        initialized.state,
        current.state,
        closed
      ];

      phases.forEach((state, index) => {
        const transition = transitionMcpLifecycleV1(state, {
          jsonrpc: "2.0",
          id: `operation-${method}-${String(index)}`,
          method,
          ...(method === "tools/call"
            ? { params: { name: "unregistered", arguments: {} } }
            : {})
        });

        expect(transition.state.protectedForwardingEnabled).toBe(false);
        expect(transition.state.serverCapabilities).toEqual({});
        expect(transition.response).toHaveProperty("error");
        expect(transition.response).not.toHaveProperty("result.tools");
        expect(transition.response).not.toHaveProperty("result.content");
      });
    }
  );

  it.each(["tools/list", "tools/call"])(
    "silently discards a notification-shaped %s operation without changing readiness",
    (method) => {
      const current = ready();
      const transition = transitionMcpLifecycleV1(current.state, {
        jsonrpc: "2.0",
        method,
        params: {}
      });

      expect(transition.state).toEqual(current.state);
      expect(transition.response).toBeNull();
      expect(transition.state.protectedForwardingEnabled).toBe(false);
    }
  );
});
