import { randomUUID } from "node:crypto";
import { TLSSocket } from "node:tls";
import { isIP } from "node:net";

import express, {
  type ErrorRequestHandler,
  type Request,
  type RequestHandler,
  type Response
} from "express";
import { z } from "zod";

import {
  closeMcpLifecycleV1,
  initialMcpLifecycleStateV1,
  selectedMcpProtocolVersionV1,
  transitionMcpLifecycleV1,
  type McpLifecycleStateV1
} from "../protocol/initialization-v1.js";
import {
  discoveryResultV1Schema
} from "../contracts/boundary-v1.js";
import {
  authenticatedClientPrincipalV1Schema,
  bindAuthenticatedIdentityToSessionV1,
  type AuthenticatedClientPrincipalV1,
  type AuthenticatedSessionIdentityBindingV1,
  type ClientAuthenticatorV1
} from "../identity/client-authentication-v1.js";
import { DisposableSessionStateRepositoryV1 } from "../identity/session-isolation-v1.js";

const DEFAULT_MAX_JSON_BODY_BYTES = 64 * 1024;
const MAX_CONFIGURED_JSON_BODY_BYTES = 1024 * 1024;
const SESSION_ID_PATTERN = /^[A-Za-z0-9._~-]{1,128}$/u;

export interface InitializationHttpAppV1Options {
  readonly clientAuthenticator: ClientAuthenticatorV1;
  readonly maxJsonBodyBytes?: number;
  readonly sessionIdFactory?: () => string;
  readonly sessionStateRepository?: DisposableSessionStateRepositoryV1;
  readonly discovery?: {
    readonly provider: (request: {
      readonly requestId: string;
      readonly session: AuthenticatedSessionIdentityBindingV1;
    }) => unknown;
    readonly requestIdFactory?: () => string;
  };
  /**
   * Optional call-time adapter. The adapter is invoked only for an
   * authenticated, READY_NON_FORWARDING session. It must perform route
   * resolution, policy evaluation, and durable decision recording; this
   * transport never forwards credentials or invokes a downstream directly.
   */
  readonly toolCall?: {
    readonly provider: (request: {
      readonly requestId: string;
      readonly protocolRequestId: string | number;
      readonly session: AuthenticatedSessionIdentityBindingV1;
      readonly name: string;
      readonly arguments: Record<string, unknown>;
      readonly signal: AbortSignal;
    }) => unknown;
  };
}

interface InitializationSessionV1 {
  state: McpLifecycleStateV1;
}

interface ErrorWithType {
  readonly type?: unknown;
}

function sendSafeError(
  response: Response,
  status: number,
  code: number,
  message: string
): void {
  response.status(status).type("application/json").json({
    jsonrpc: "2.0",
    id: null,
    error: { code, message }
  });
}

function isLoopbackAddress(address: string | undefined): boolean {
  if (address === undefined) {
    return false;
  }

  if (address === "::1" || address === "0:0:0:0:0:0:0:1") {
    return true;
  }

  const ipv4 = address.startsWith("::ffff:") ? address.slice(7) : address;
  return isIP(ipv4) === 4 && ipv4.split(".")[0] === "127";
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    const parsed = new URL(origin);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return false;
    }

    const hostname = parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]")
      ? parsed.hostname.slice(1, -1)
      : parsed.hostname;
    return hostname === "localhost" || isLoopbackAddress(hostname);
  } catch {
    return false;
  }
}

function acceptsStreamableHttp(request: Request): boolean {
  const accept = request.headers.accept;
  if (accept === undefined) {
    return false;
  }

  const mediaTypes = new Set(
    accept
      .split(",")
      .map((entry) => entry.split(";", 1)[0]?.trim().toLowerCase())
      .filter((entry): entry is string => entry !== undefined && entry.length > 0)
  );
  return mediaTypes.has("application/json") && mediaTypes.has("text/event-stream");
}

function validateMaxJsonBodyBytes(value: number | undefined): number {
  const selected = value ?? DEFAULT_MAX_JSON_BODY_BYTES;
  if (
    !Number.isSafeInteger(selected) ||
    selected <= 0 ||
    selected > MAX_CONFIGURED_JSON_BODY_BYTES
  ) {
    throw new RangeError(
      "maxJsonBodyBytes must be a positive safe integer no greater than " +
        String(MAX_CONFIGURED_JSON_BODY_BYTES)
    );
  }
  return selected;
}

function issueSessionId(
  sessions: ReadonlyMap<string, InitializationSessionV1>,
  factory: () => string
): string {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const candidate = factory();
    if (SESSION_ID_PATTERN.test(candidate) && !sessions.has(candidate)) {
      return candidate;
    }
  }
  throw new Error("Unable to issue a unique transport session identifier");
}

function sessionIdHeader(request: Request): string | undefined {
  const value = request.headers["mcp-session-id"];
  return typeof value === "string" ? value : undefined;
}

function protocolVersionHeader(request: Request): string | undefined {
  const value = request.headers["mcp-protocol-version"];
  return typeof value === "string" ? value : undefined;
}

function methodFromUnknown(input: unknown): string | undefined {
  if (input === null || typeof input !== "object") {
    return undefined;
  }
  const method: unknown = (input as Record<string, unknown>)["method"];
  return typeof method === "string" ? method : undefined;
}

const toolsListRequestV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: z.union([z.string().min(1).max(128), z.number().int()]),
    method: z.literal("tools/list"),
    params: z.object({}).strict().optional()
  })
  .strict();
const toolCallRequestV1Schema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: z.union([z.string().min(1).max(128), z.number().int()]),
    method: z.literal("tools/call"),
    params: z
      .object({
        name: z.string().min(1).max(256),
        arguments: z.record(z.string(), z.unknown()).default({})
      })
      .strict()
  })
  .strict();
const gatewayOwnedAnnotationKeys = new Set([
  "_meta",
  "gateway",
  "contentTrust",
  "callTimeAuthorizationRequired",
  "coverage"
]);

function untrustedAnnotationsForWire(
  annotations: Record<string, unknown> | null
): Record<string, unknown> | null {
  if (annotations === null) {
    return null;
  }
  return Object.fromEntries(
    Object.entries(annotations).filter(([key]) => !gatewayOwnedAnnotationKeys.has(key))
  );
}

function certificateTimeForAuthentication(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

export function createInitializationHttpAppV1(
  options: InitializationHttpAppV1Options
): express.Express {
  if (typeof options.clientAuthenticator !== "function") {
    throw new TypeError("A trusted client authenticator is required");
  }
  const maxJsonBodyBytes = validateMaxJsonBodyBytes(options.maxJsonBodyBytes);
  const sessionIdFactory = options.sessionIdFactory ?? randomUUID;
  const sessionStateRepository =
    options.sessionStateRepository ?? new DisposableSessionStateRepositoryV1();
  const sessions = new Map<string, InitializationSessionV1>();
  const requestPrincipals = new WeakMap<Request, AuthenticatedClientPrincipalV1>();
  const app = express();

  app.disable("x-powered-by");

  const requireLoopback: RequestHandler = (request, response, next) => {
    if (!isLoopbackAddress(request.socket.remoteAddress)) {
      sendSafeError(response, 403, -32003, "Loopback transport is required");
      return;
    }

    const origin = request.headers.origin;
    if (origin !== undefined && !isLoopbackOrigin(origin)) {
      sendSafeError(response, 403, -32003, "Origin is not permitted");
      return;
    }
    next();
  };

  const requireAuthenticatedClient: RequestHandler = async (request, response, next) => {
    let candidate: unknown;
    try {
      const tlsSocket = request.socket instanceof TLSSocket ? request.socket : null;
      const peerCertificate = tlsSocket?.getPeerCertificate();
      candidate = await options.clientAuthenticator({
        transport: "STREAMABLE_HTTP",
        remoteAddress: request.socket.remoteAddress ?? "",
        authorizationHeader: request.headers.authorization,
        trustedTlsPeer: tlsSocket === null
          ? null
          : {
              schemaVersion: "1.0.0",
              authorized: tlsSocket.authorized,
              authorizationError: tlsSocket.authorizationError instanceof Error
                ? tlsSocket.authorizationError.message
                : null,
              protocol: tlsSocket.getProtocol(),
              certificate: {
                fingerprintSha256: peerCertificate !== undefined &&
                  typeof peerCertificate.fingerprint256 === "string"
                  ? peerCertificate.fingerprint256.replaceAll(":", "").toLowerCase()
                  : undefined,
                validFrom: certificateTimeForAuthentication(peerCertificate?.valid_from),
                validTo: certificateTimeForAuthentication(peerCertificate?.valid_to),
                extendedKeyUsageOids: peerCertificate?.ext_key_usage ?? []
              }
            }
      });
    } catch {
      sendSafeError(response, 503, -32004, "Client authentication is unavailable");
      return;
    }

    if (candidate === null || candidate === undefined) {
      sendSafeError(response, 401, -32004, "Client authentication is required");
      return;
    }

    const principal = authenticatedClientPrincipalV1Schema.safeParse(candidate);
    if (!principal.success) {
      sendSafeError(response, 503, -32004, "Client authentication returned invalid identity");
      return;
    }

    requestPrincipals.set(request, principal.data);
    next();
  };

  const authenticatedPrincipal = (request: Request): AuthenticatedClientPrincipalV1 => {
    const principal = requestPrincipals.get(request);
    if (principal === undefined) {
      throw new Error("Authenticated principal is unavailable");
    }
    return principal;
  };

  app.use("/mcp", requireLoopback);
  app.use("/mcp", requireAuthenticatedClient);
  app.use(
    "/mcp",
    express.json({
      inflate: false,
      limit: maxJsonBodyBytes,
      strict: true,
      type: "application/json"
    })
  );

  app.get("/mcp", (_request, response) => {
    response.setHeader("Allow", "POST, DELETE");
    sendSafeError(response, 405, -32601, "SSE streaming is not available");
  });

  app.post("/mcp", async (request, response) => {
    if (!acceptsStreamableHttp(request)) {
      sendSafeError(
        response,
        406,
        -32600,
        "Accept must include application/json and text/event-stream"
      );
      return;
    }
    if (!request.is("application/json")) {
      sendSafeError(response, 415, -32600, "Content-Type must be application/json");
      return;
    }

    const requestedSessionId = sessionIdHeader(request);
    if (requestedSessionId === undefined) {
      const method = methodFromUnknown(request.body);
      if (method !== "initialize" && method !== "ping") {
        sendSafeError(response, 400, -32001, "MCP session identifier is required");
        return;
      }
      const transition = transitionMcpLifecycleV1(initialMcpLifecycleStateV1, request.body, {
        discoveryEnabled: options.discovery !== undefined
      });
      if (transition.state.phase === "INITIALIZE_RESPONSE_SENT") {
        const issuedSessionId = issueSessionId(sessions, sessionIdFactory);
        const identityBinding = bindAuthenticatedIdentityToSessionV1(
          authenticatedPrincipal(request),
          issuedSessionId
        );
        sessionStateRepository.createSession(identityBinding);
        sessions.set(issuedSessionId, { state: transition.state });
        response.setHeader("Mcp-Session-Id", issuedSessionId);
      }

      if (transition.response === null) {
        response.status(202).end();
      } else {
        response.status(200).type("application/json").json(transition.response);
      }
      return;
    }

    const session = sessions.get(requestedSessionId);
    if (session === undefined) {
      sendSafeError(response, 404, -32001, "MCP session was not found");
      return;
    }
    let currentIdentityBinding: AuthenticatedSessionIdentityBindingV1;
    try {
      currentIdentityBinding = sessionStateRepository.authorizeSession(
        authenticatedPrincipal(request),
        requestedSessionId
      );
    } catch {
      sendSafeError(response, 404, -32001, "MCP session was not found");
      return;
    }
    if (protocolVersionHeader(request) !== selectedMcpProtocolVersionV1) {
      sendSafeError(response, 400, -32600, "MCP protocol version is missing or unsupported");
      return;
    }

    const listRequest = toolsListRequestV1Schema.safeParse(request.body);
    if (listRequest.success && options.discovery !== undefined) {
      if (session.state.phase !== "READY_NON_FORWARDING") {
        const transition = transitionMcpLifecycleV1(session.state, request.body, {
          discoveryEnabled: true
        });
        response.status(200).type("application/json").json(transition.response);
        return;
      }
      try {
        const discovery = discoveryResultV1Schema.parse(options.discovery.provider({
          requestId: options.discovery.requestIdFactory?.() ?? randomUUID(),
          session: currentIdentityBinding
        }));
        if (
          discovery.sessionId !== currentIdentityBinding.stateNamespace ||
          discovery.coverage !== "UNPROTECTED"
        ) {
          throw new Error("Discovery provider returned an invalid runtime binding");
        }
        const payload = {
          jsonrpc: "2.0",
          id: listRequest.data.id,
          result: {
            tools: discovery.tools.map((tool) => ({
              name: tool.route.exposedName,
              ...(tool.title === null ? {} : { title: tool.title }),
              ...(tool.description === null ? {} : { description: tool.description }),
              inputSchema: tool.inputSchema,
              ...(tool.outputSchema === null ? {} : { outputSchema: tool.outputSchema }),
              ...(tool.annotations === null
                ? {}
                : { annotations: untrustedAnnotationsForWire(tool.annotations) }),
              _meta: {
                gateway: {
                  contentTrust: tool.contentTrust,
                  callTimeAuthorizationRequired: tool.callTimeAuthorizationRequired,
                  coverage: discovery.coverage
                }
              }
            }))
          }
        };
        if (Buffer.byteLength(JSON.stringify(payload), "utf8") > 1024 * 1024) {
          throw new Error("Discovery response exceeds the runtime byte limit");
        }
        response.status(200).type("application/json").json(payload);
      } catch {
        sendSafeError(response, 503, -32005, "Tool discovery is unavailable");
      }
      return;
    }

    const callRequest = toolCallRequestV1Schema.safeParse(request.body);
    if (callRequest.success && options.toolCall !== undefined) {
      if (session.state.phase !== "READY_NON_FORWARDING") {
        const transition = transitionMcpLifecycleV1(session.state, request.body, {
          discoveryEnabled: options.discovery !== undefined
        });
        session.state = transition.state;
        response.status(200).type("application/json").json(transition.response);
        return;
      }
      const controller = new AbortController();
      const abortRequest = () => { controller.abort(new Error("Client transport closed")); };
      request.once("aborted", abortRequest);
      response.once("close", abortRequest);
      try {
        const result = await options.toolCall.provider({
          requestId: randomUUID(),
          protocolRequestId: callRequest.data.id,
          session: currentIdentityBinding,
          name: callRequest.data.params.name,
          arguments: callRequest.data.params.arguments,
          signal: controller.signal
        });
        response.status(200).type("application/json").json({
          jsonrpc: "2.0",
          id: callRequest.data.id,
          result
        });
      } catch {
        if (!response.headersSent) sendSafeError(response, 503, -32006, "Tool call admission is unavailable");
      } finally {
        request.off("aborted", abortRequest);
        response.off("close", abortRequest);
      }
      return;
    }
    if (
      options.toolCall !== undefined &&
      methodFromUnknown(request.body) === "tools/call" &&
      request.body !== null && typeof request.body === "object" &&
      Object.hasOwn(request.body as Record<string, unknown>, "id")
    ) {
      const idCandidate = (request.body as Record<string, unknown>)["id"];
      const id = z.union([z.string().min(1).max(128), z.number().int()]).safeParse(idCandidate);
      response.status(200).type("application/json").json({
        jsonrpc: "2.0",
        id: id.success ? id.data : null,
        error: { code: -32602, message: "Invalid tools/call request" }
      });
      return;
    }
    if (
      options.discovery !== undefined &&
      session.state.phase === "READY_NON_FORWARDING" &&
      methodFromUnknown(request.body) === "tools/list" &&
      request.body !== null && typeof request.body === "object" &&
      Object.hasOwn(request.body as Record<string, unknown>, "id")
    ) {
      const idCandidate = (request.body as Record<string, unknown>)["id"];
      const id = z.union([z.string().min(1).max(128), z.number().int()])
        .safeParse(idCandidate);
      response.status(200).type("application/json").json({
        jsonrpc: "2.0",
        id: id.success ? id.data : null,
        error: { code: -32602, message: "Invalid tools/list request" }
      });
      return;
    }

    const transition = transitionMcpLifecycleV1(session.state, request.body, {
      discoveryEnabled: options.discovery !== undefined
    });
    session.state = transition.state;
    if (transition.response === null) {
      response.status(202).end();
    } else {
      response.status(200).type("application/json").json(transition.response);
    }
  });

  app.delete("/mcp", (request, response) => {
    const requestedSessionId = sessionIdHeader(request);
    if (requestedSessionId === undefined) {
      sendSafeError(response, 400, -32001, "MCP session identifier is required");
      return;
    }
    const session = sessions.get(requestedSessionId);
    if (session === undefined) {
      sendSafeError(response, 404, -32001, "MCP session was not found");
      return;
    }
    try {
      sessionStateRepository.authorizeSession(
        authenticatedPrincipal(request),
        requestedSessionId
      );
    } catch {
      sendSafeError(response, 404, -32001, "MCP session was not found");
      return;
    }
    if (protocolVersionHeader(request) !== selectedMcpProtocolVersionV1) {
      sendSafeError(response, 400, -32600, "MCP protocol version is missing or unsupported");
      return;
    }

    session.state = closeMcpLifecycleV1(session.state);
    sessionStateRepository.closeSession(authenticatedPrincipal(request), requestedSessionId);
    sessions.delete(requestedSessionId);
    response.status(204).end();
  });

  const safeErrorHandler: ErrorRequestHandler = (error, _request, response, next) => {
    void next;
    const errorType = typeof error === "object" && error !== null
      ? (error as ErrorWithType).type
      : undefined;
    if (errorType === "entity.too.large") {
      sendSafeError(response, 413, -32600, "JSON request body exceeds the configured limit");
      return;
    }
    if (errorType === "encoding.unsupported") {
      sendSafeError(response, 415, -32600, "Compressed request bodies are not supported");
      return;
    }
    if (error instanceof SyntaxError) {
      sendSafeError(response, 400, -32700, "Invalid JSON request body");
      return;
    }
    sendSafeError(response, 500, -32603, "Internal transport error");
  };
  app.use(safeErrorHandler);

  return app;
}
