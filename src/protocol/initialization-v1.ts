import { z } from "zod";

import {
  boundedProtocolJsonObjectV1Schema,
  boundedProtocolJsonV1Schema,
  untrustedProtocolJsonShapeGuardV1Schema
} from "../contracts/boundary-v1.js";

export const supportedMcpProtocolVersionsV1 = ["2025-06-18"] as const;
export const selectedMcpProtocolVersionV1 = supportedMcpProtocolVersionsV1[0];

const jsonRpcIdV1Schema = z.union([
  z.string().min(1).max(128),
  z.number().int().min(-Number.MAX_SAFE_INTEGER).max(Number.MAX_SAFE_INTEGER)
]);

const implementationV1Schema = z
  .object({
    name: z.string().trim().min(1).max(128),
    title: z.string().trim().min(1).max(256).optional(),
    version: z.string().trim().min(1).max(64)
  })
  .strict();

const openCapabilityV1Schema = boundedProtocolJsonObjectV1Schema;
const clientCapabilitiesV1Schema = untrustedProtocolJsonShapeGuardV1Schema
  .pipe(
    z
      .object({
        experimental: z
          .record(z.string().min(1).max(128), boundedProtocolJsonObjectV1Schema)
          .optional(),
        roots: z
          .object({ listChanged: z.boolean().optional() })
          .catchall(boundedProtocolJsonV1Schema)
          .optional(),
        sampling: openCapabilityV1Schema.optional(),
        elicitation: openCapabilityV1Schema.optional()
      })
      .catchall(openCapabilityV1Schema)
  )
  .superRefine((capabilities, context) => {
    if (Object.keys(capabilities).length > 128) {
      context.addIssue({
        code: "custom",
        message: "Client capability declarations exceed the negotiated state limit"
      });
    }
  });

export const initializeRequestV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: jsonRpcIdV1Schema,
    method: z.literal("initialize"),
    params: z
      .object({
        protocolVersion: z.string().regex(/^\d{4}-\d{2}-\d{2}$/u),
        capabilities: clientCapabilitiesV1Schema,
        clientInfo: implementationV1Schema,
        _meta: boundedProtocolJsonObjectV1Schema.optional()
      })
      .strict()
  })
  .strict();

export const initializedNotificationV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    method: z.literal("notifications/initialized"),
    params: boundedProtocolJsonObjectV1Schema.optional()
  })
  .strict();

export const pingRequestV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: jsonRpcIdV1Schema,
    method: z.literal("ping"),
    params: boundedProtocolJsonObjectV1Schema.optional()
  })
  .strict();

const genericRequestV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: jsonRpcIdV1Schema,
    method: z.string().min(1).max(256),
    params: boundedProtocolJsonV1Schema.optional()
  })
  .strict();

const genericNotificationV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    method: z.string().min(1).max(256),
    params: boundedProtocolJsonV1Schema.optional()
  })
  .strict();

const gatewayServerCapabilitiesV1Schema = z
  .object({
    tools: z
      .object({
        listChanged: z.literal(false)
      })
      .strict()
      .optional()
  })
  .strict();

export const initializeResponseV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: jsonRpcIdV1Schema,
    result: z
      .object({
        protocolVersion: z.literal(selectedMcpProtocolVersionV1),
        capabilities: gatewayServerCapabilitiesV1Schema,
        serverInfo: implementationV1Schema
      })
      .strict()
  })
  .strict();

export const jsonRpcErrorResponseV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: jsonRpcIdV1Schema.nullable(),
    error: z
      .object({
        code: z.number().int(),
        message: z.string().trim().min(1).max(512),
        data: boundedProtocolJsonObjectV1Schema.optional()
      })
      .strict()
  })
  .strict();

const pingResponseV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: jsonRpcIdV1Schema,
    result: z.object({}).strict()
  })
  .strict();

export const lifecycleResponseV1Schema = z.union([
  initializeResponseV1Schema,
  jsonRpcErrorResponseV1Schema,
  pingResponseV1Schema
]);

export const mcpLifecycleStateV1Schema = z
  .object({
    phase: z.enum([
      "NEW",
      "INITIALIZE_RESPONSE_SENT",
      "READY_NON_FORWARDING",
      "REJECTED",
      "CLOSED"
    ]),
    initializeRequestId: jsonRpcIdV1Schema.nullable(),
    requestedProtocolVersion: z.string().nullable(),
    negotiatedProtocolVersion: z.literal(selectedMcpProtocolVersionV1).nullable(),
    declaredClientCapabilities: z.array(z.string().min(1).max(128)).max(128),
    unrecognizedClientCapabilities: z.array(z.string().min(1).max(128)).max(128),
    serverCapabilities: gatewayServerCapabilitiesV1Schema,
    protectedForwardingEnabled: z.literal(false)
  })
  .strict()
  .superRefine((state, context) => {
    const negotiated = state.phase === "INITIALIZE_RESPONSE_SENT" ||
      state.phase === "READY_NON_FORWARDING";
    if (negotiated !== (state.negotiatedProtocolVersion !== null)) {
      context.addIssue({
        code: "custom",
        path: ["negotiatedProtocolVersion"],
        message: "Negotiated lifecycle phases require exactly one protocol version"
      });
    }
    if (negotiated !== (state.initializeRequestId !== null)) {
      context.addIssue({
        code: "custom",
        path: ["initializeRequestId"],
        message: "Negotiated lifecycle phases require the initialize request ID"
      });
    }
  });

export type McpLifecycleStateV1 = z.infer<typeof mcpLifecycleStateV1Schema>;
export type LifecycleResponseV1 = z.infer<typeof lifecycleResponseV1Schema>;

export interface McpLifecycleTransitionV1 {
  readonly state: McpLifecycleStateV1;
  readonly response: LifecycleResponseV1 | null;
}

export interface McpLifecycleOptionsV1 {
  readonly discoveryEnabled?: boolean;
}

export const initialMcpLifecycleStateV1: McpLifecycleStateV1 = Object.freeze({
  phase: "NEW",
  initializeRequestId: null,
  requestedProtocolVersion: null,
  negotiatedProtocolVersion: null,
  declaredClientCapabilities: [],
  unrecognizedClientCapabilities: [],
  serverCapabilities: {},
  protectedForwardingEnabled: false
});

const knownClientCapabilities = new Set([
  "experimental",
  "roots",
  "sampling",
  "elicitation"
]);

const gatewayServerInfo = Object.freeze({
  name: "agent-security-mcp-gateway",
  title: "Agent Security MCP Gateway",
  version: "0.2.0"
});

function errorResponse(
  id: z.infer<typeof jsonRpcIdV1Schema> | null,
  code: number,
  message: string,
  data?: Record<string, z.infer<typeof z.json>>
): LifecycleResponseV1 {
  return jsonRpcErrorResponseV1Schema.parse({
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
      ...(data === undefined ? {} : { data })
    }
  });
}

function requestIdFromUnknown(input: unknown): z.infer<typeof jsonRpcIdV1Schema> | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const id: unknown = (input as Record<string, unknown>)["id"];
  const parsed = jsonRpcIdV1Schema.safeParse(id);
  return parsed.success ? parsed.data : null;
}

function transitionInitialize(
  request: z.infer<typeof initializeRequestV1Schema>,
  options: McpLifecycleOptionsV1
): McpLifecycleTransitionV1 {
  const declaredClientCapabilities = Object.keys(request.params.capabilities).sort();
  const unrecognizedClientCapabilities = declaredClientCapabilities.filter(
    (capability) => !knownClientCapabilities.has(capability)
  );
  const serverCapabilities = options.discoveryEnabled === true
    ? { tools: { listChanged: false as const } }
    : {};
  const state = mcpLifecycleStateV1Schema.parse({
    phase: "INITIALIZE_RESPONSE_SENT",
    initializeRequestId: request.id,
    requestedProtocolVersion: request.params.protocolVersion,
    negotiatedProtocolVersion: selectedMcpProtocolVersionV1,
    declaredClientCapabilities,
    unrecognizedClientCapabilities,
    serverCapabilities,
    protectedForwardingEnabled: false
  });
  const response = initializeResponseV1Schema.parse({
    jsonrpc: "2.0",
    id: request.id,
    result: {
      protocolVersion: selectedMcpProtocolVersionV1,
      capabilities: serverCapabilities,
      serverInfo: gatewayServerInfo
    }
  });
  return { state, response };
}

export function transitionMcpLifecycleV1(
  currentStateInput: McpLifecycleStateV1,
  input: unknown,
  options: McpLifecycleOptionsV1 = {}
): McpLifecycleTransitionV1 {
  const currentState = mcpLifecycleStateV1Schema.parse(currentStateInput);

  if (currentState.phase === "CLOSED" || currentState.phase === "REJECTED") {
    if (genericNotificationV1Schema.safeParse(input).success) {
      return { state: currentState, response: null };
    }
    return {
      state: currentState,
      response: errorResponse(requestIdFromUnknown(input), -32000, "MCP session is closed")
    };
  }

  const ping = pingRequestV1Schema.safeParse(input);
  if (ping.success) {
    return {
      state: currentState,
      response: pingResponseV1Schema.parse({
        jsonrpc: "2.0",
        id: ping.data.id,
        result: {}
      })
    };
  }

  if (currentState.phase === "NEW") {
    const initialize = initializeRequestV1Schema.safeParse(input);
    if (initialize.success) {
      return transitionInitialize(initialize.data, options);
    }

    const genericRequest = genericRequestV1Schema.safeParse(input);
    if (genericRequest.success) {
      return {
        state: currentState,
        response: errorResponse(
          genericRequest.data.id,
          -32002,
          "MCP server has not been initialized"
        )
      };
    }

    if (genericNotificationV1Schema.safeParse(input).success) {
      return { state: currentState, response: null };
    }

    return {
      state: currentState,
      response: errorResponse(requestIdFromUnknown(input), -32600, "Invalid initialize request")
    };
  }

  if (currentState.phase === "INITIALIZE_RESPONSE_SENT") {
    const initialized = initializedNotificationV1Schema.safeParse(input);
    if (initialized.success) {
      return {
        state: mcpLifecycleStateV1Schema.parse({
          ...currentState,
          phase: "READY_NON_FORWARDING"
        }),
        response: null
      };
    }

    const genericNotification = genericNotificationV1Schema.safeParse(input);
    if (genericNotification.success) {
      return {
        state: currentState,
        response: null
      };
    }

    return {
      state: currentState,
      response: errorResponse(
        requestIdFromUnknown(input),
        -32002,
        "MCP initialization acknowledgement is required"
      )
    };
  }

  const duplicateInitialize = initializeRequestV1Schema.safeParse(input);
  if (duplicateInitialize.success) {
    return {
      state: currentState,
      response: errorResponse(
        duplicateInitialize.data.id,
        -32600,
        "MCP session is already initialized"
      )
    };
  }

  const operationRequest = genericRequestV1Schema.safeParse(input);
  if (operationRequest.success) {
    return {
      state: currentState,
      response: errorResponse(
        operationRequest.data.id,
        -32601,
        "Method is unavailable while the gateway is non-forwarding",
        { method: operationRequest.data.method, coverage: "UNPROTECTED" }
      )
    };
  }

  if (genericNotificationV1Schema.safeParse(input).success) {
    return { state: currentState, response: null };
  }

  return {
    state: currentState,
    response: errorResponse(requestIdFromUnknown(input), -32600, "Invalid JSON-RPC request")
  };
}

export function closeMcpLifecycleV1(
  currentStateInput: McpLifecycleStateV1
): McpLifecycleStateV1 {
  const currentState = mcpLifecycleStateV1Schema.parse(currentStateInput);
  return mcpLifecycleStateV1Schema.parse({
    ...currentState,
    phase: "CLOSED",
    negotiatedProtocolVersion: null,
    initializeRequestId: null
  });
}
