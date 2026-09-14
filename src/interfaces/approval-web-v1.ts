import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import express, {
  type ErrorRequestHandler,
  type Request,
  type RequestHandler,
  type Response
} from "express";
import { z } from "zod";

import {
  approvalV1Schema,
  executionOutcomeV1Schema,
  type ApprovalV1,
  type ExecutionOutcomeV1
} from "../contracts/trajectory-v1.js";
import { identifierV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";
import {
  trustworthyActionInterfaceV1Schema,
  type TrustworthyActionInterfaceV1
} from "./trustworthy-interface-v1.js";

const digestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const opaqueTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const revisionSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const authenticationMethodSchema = z.enum(["MUTUAL_TLS", "OIDC", "WEBAUTHN"]);

export const approvalWebHumanPrincipalV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  humanId: identifierV1Schema,
  authenticationMethod: authenticationMethodSchema,
  credentialId: identifierV1Schema,
  identityRevision: revisionSchema,
  authenticatedAt: utcTimestampV1Schema
}).strict();

export const approvalWebSessionV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  sessionIdDigest: digestSchema,
  csrfTokenDigest: digestSchema,
  humanId: identifierV1Schema,
  authenticationMethod: authenticationMethodSchema,
  credentialId: identifierV1Schema,
  identityRevision: revisionSchema,
  policyScopeIds: z.array(identifierV1Schema).min(1).max(128).superRefine((values, context) => {
    if (new Set(values).size !== values.length) {
      context.addIssue({ code: "custom", message: "Policy scopes must be unique" });
    }
  }),
  createdAt: utcTimestampV1Schema,
  expiresAt: utcTimestampV1Schema
}).strict().superRefine((session, context) => {
  if (Date.parse(session.expiresAt) <= Date.parse(session.createdAt)) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "Session expiry must follow creation" });
  }
});

export const approvalWebRecordV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  revision: revisionSchema,
  approval: approvalV1Schema,
  view: trustworthyActionInterfaceV1Schema,
  outcome: executionOutcomeV1Schema.nullable()
}).strict().superRefine((record, context) => {
  const { approval, view, outcome } = record;
  if (view.decision !== "REQUIRE_APPROVAL" ||
    approval.requestId !== view.requestId || approval.actionId !== view.actionId ||
    approval.decisionId !== view.decisionId || approval.sessionId !== view.requester.sessionId ||
    approval.route.serverId !== view.route.serverId || approval.route.toolName !== view.route.toolName ||
    approval.route.routeId !== view.route.routeId || approval.route.schemaDigest !== view.route.schemaDigest ||
    approval.route.credentialAudienceId !== view.route.credentialAudienceId ||
    approval.route.policyScopeId !== view.route.policyScopeId) {
    context.addIssue({ code: "custom", message: "Approval web record bindings must match" });
  }
  if (outcome !== null && (outcome.requestId !== approval.requestId ||
    outcome.actionId !== approval.actionId || outcome.decisionId !== approval.decisionId ||
    outcome.approvalId !== approval.approvalId || outcome.sessionId !== approval.sessionId)) {
    context.addIssue({ code: "custom", path: ["outcome"], message: "Outcome must match the approval" });
  }
});

export const approvalWebDecisionRequestV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  decision: z.enum(["APPROVE", "DENY"])
}).strict();

export type ApprovalWebHumanPrincipalV1 = z.infer<typeof approvalWebHumanPrincipalV1Schema>;
export type ApprovalWebSessionV1 = z.infer<typeof approvalWebSessionV1Schema>;
export type ApprovalWebRecordV1 = z.infer<typeof approvalWebRecordV1Schema>;
export type ApprovalWebDecisionRequestV1 = z.infer<typeof approvalWebDecisionRequestV1Schema>;

export interface ApprovalWebStaticAssetV1 {
  readonly contentType: "text/html; charset=utf-8" | "text/css; charset=utf-8" |
    "application/javascript; charset=utf-8";
  readonly body: string | Uint8Array;
}

export interface ApprovalWebStoreV1 {
  createSession(input: {
    readonly sessionIdDigest: string;
    readonly csrfTokenDigest: string;
    readonly principal: ApprovalWebHumanPrincipalV1;
    readonly createdAt: string;
    readonly expiresAt: string;
  }): Promise<ApprovalWebSessionV1>;
  readAuthorizedSession(input: {
    readonly sessionIdDigest: string;
    readonly principal: ApprovalWebHumanPrincipalV1;
    readonly now: string;
  }): Promise<ApprovalWebSessionV1 | null>;
  listPending(session: ApprovalWebSessionV1): Promise<readonly ApprovalWebRecordV1[]>;
  readApproval(session: ApprovalWebSessionV1, approvalId: string): Promise<ApprovalWebRecordV1 | null>;
  decide(input: {
    readonly session: ApprovalWebSessionV1;
    readonly approvalId: string;
    readonly decision: ApprovalWebDecisionRequestV1["decision"];
    readonly expectedRevision: number;
    readonly decidedAt: string;
  }): Promise<ApprovalWebRecordV1>;
}

export interface ApprovalWebAppV1Options {
  readonly origin: string;
  readonly authenticateHuman: (
    request: Request
  ) => ApprovalWebHumanPrincipalV1 | null | Promise<ApprovalWebHumanPrincipalV1 | null>;
  readonly store: ApprovalWebStoreV1;
  readonly readStaticAsset: (
    path: "/index.html" | `/assets/${string}`
  ) => ApprovalWebStaticAssetV1 | null | Promise<ApprovalWebStaticAssetV1 | null>;
  readonly clock?: () => Date;
  readonly tokenFactory?: () => string;
  readonly sessionLifetimeMs?: number;
  readonly maxJsonBodyBytes?: number;
  readonly maxStaticAssetBytes?: number;
}

export class ApprovalWebStaleDecisionV1 extends Error {
  public constructor() {
    super("Approval state is stale");
    this.name = "ApprovalWebStaleDecisionV1";
  }
}

const cookieName = "__Host-agent_security_approval";

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function equalDigest(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function safeError(response: Response, status: number, code: string, message: string): void {
  response.status(status).type("application/json").json({
    schemaVersion: "1.0.0",
    error: { code, message }
  });
}

function parseCookie(request: Request): string | null {
  const header = request.headers.cookie;
  if (header === undefined) return null;
  const values = header.split(";").map((item) => item.trim()).filter((item) =>
    item.startsWith(`${cookieName}=`));
  if (values.length !== 1) return null;
  const value = values[0]?.slice(cookieName.length + 1);
  const parsed = opaqueTokenSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function parseIfMatch(request: Request): number | null {
  const header = request.headers["if-match"];
  if (typeof header !== "string") return null;
  const match = /^"([1-9][0-9]{0,14})"$/u.exec(header);
  if (match === null) return null;
  const revision = Number(match[1]);
  return Number.isSafeInteger(revision) ? revision : null;
}

function validateOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" ||
    url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    throw new TypeError("Approval web origin must be an HTTPS origin");
  }
  return url.origin;
}

function staticAssetPath(requestPath: string): "/index.html" | `/assets/${string}` | null {
  if (requestPath === "/approval" || requestPath === "/approval/") return "/index.html";
  const match = /^\/approval\/assets\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})$/u.exec(requestPath);
  return match?.[1] === undefined ? null : `/assets/${match[1]}`;
}

function recordForScope(recordInput: ApprovalWebRecordV1, session: ApprovalWebSessionV1): ApprovalWebRecordV1 {
  const record = approvalWebRecordV1Schema.parse(recordInput);
  if (!session.policyScopeIds.includes(record.view.route.policyScopeId)) {
    throw new Error("Store returned approval outside the authorized policy scopes");
  }
  return record;
}

function listItem(record: ApprovalWebRecordV1): Record<string, unknown> {
  return {
    approvalId: record.approval.approvalId,
    revision: record.revision,
    requestId: record.approval.requestId,
    interfaceId: record.view.interfaceId,
    policyScopeId: record.view.route.policyScopeId,
    state: record.approval.state,
    requestedAt: record.approval.requestedAt,
    expiresAt: record.approval.expiresAt,
    riskTier: record.view.riskTier,
    actionEffect: record.view.actionEffect,
    serverId: record.view.route.serverId,
    toolName: record.view.route.toolName,
    targetCount: record.view.targets.length
  };
}

export function createApprovalWebAppV1(options: ApprovalWebAppV1Options): express.Express {
  if (typeof options.authenticateHuman !== "function" || typeof options.readStaticAsset !== "function") {
    throw new TypeError("Approval web authentication and static asset providers are required");
  }
  const origin = validateOrigin(options.origin);
  const clock = options.clock ?? (() => new Date());
  const tokenFactory = options.tokenFactory ?? (() => randomBytes(32).toString("base64url"));
  const sessionLifetimeMs = options.sessionLifetimeMs ?? 15 * 60_000;
  if (!Number.isSafeInteger(sessionLifetimeMs) || sessionLifetimeMs < 1_000 ||
    sessionLifetimeMs > 8 * 60 * 60_000) {
    throw new RangeError("Approval web session lifetime must be between one second and eight hours");
  }
  const maxJsonBodyBytes = options.maxJsonBodyBytes ?? 4 * 1024;
  const maxStaticAssetBytes = options.maxStaticAssetBytes ?? 512 * 1024;
  for (const [name, value, maximum] of [
    ["JSON body", maxJsonBodyBytes, 64 * 1024],
    ["static asset", maxStaticAssetBytes, 2 * 1024 * 1024]
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
      throw new RangeError(`${name} byte limit is invalid`);
    }
  }

  const app = express();
  const principals = new WeakMap<Request, ApprovalWebHumanPrincipalV1>();
  const sessions = new WeakMap<Request, ApprovalWebSessionV1>();
  app.disable("x-powered-by");
  app.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("Strict-Transport-Security", "max-age=31536000");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    next();
  });

  const authenticate: RequestHandler = async (request, response, next) => {
    try {
      const candidate = await options.authenticateHuman(request);
      if (candidate === null) {
        safeError(response, 401, "approval.authentication_required", "Human authentication is required");
        return;
      }
      principals.set(request, approvalWebHumanPrincipalV1Schema.parse(candidate));
      next();
    } catch {
      safeError(response, 503, "approval.authentication_unavailable", "Human authentication is unavailable");
    }
  };

  const requireSameOriginFetch: RequestHandler = (request, response, next) => {
    const suppliedOrigin = request.headers.origin;
    const safeRead = request.method === "GET" || request.method === "HEAD";
    if (request.headers["sec-fetch-site"] !== "same-origin" ||
      (safeRead ? suppliedOrigin !== undefined && suppliedOrigin !== origin : suppliedOrigin !== origin)) {
      safeError(response, 403, "approval.request_integrity_denied", "Approval request integrity check failed");
      return;
    }
    next();
  };

  const authorizeSession: RequestHandler = async (request, response, next) => {
    const rawSession = parseCookie(request);
    const principal = principals.get(request);
    if (rawSession === null || principal === undefined) {
      safeError(response, 401, "approval.session_required", "Approval session is required");
      return;
    }
    try {
      const candidate = await options.store.readAuthorizedSession({
        sessionIdDigest: digest(rawSession),
        principal,
        now: clock().toISOString()
      });
      if (candidate === null) {
        safeError(response, 401, "approval.session_required", "Approval session is required");
        return;
      }
      const session = approvalWebSessionV1Schema.parse(candidate);
      if (session.humanId !== principal.humanId || session.authenticationMethod !== principal.authenticationMethod ||
        session.credentialId !== principal.credentialId || session.identityRevision !== principal.identityRevision ||
        Date.parse(session.expiresAt) <= clock().getTime()) {
        safeError(response, 401, "approval.session_required", "Approval session is required");
        return;
      }
      sessions.set(request, session);
      next();
    } catch {
      safeError(response, 503, "approval.session_unavailable", "Approval session is unavailable");
    }
  };

  app.get(["/approval", "/approval/", "/approval/assets/:asset"], authenticate, async (request, response) => {
    const path = staticAssetPath(request.path);
    if (path === null) {
      safeError(response, 404, "approval.not_found", "Approval resource was not found");
      return;
    }
    try {
      const asset = await options.readStaticAsset(path);
      if (asset === null || !new Set([
        "text/html; charset=utf-8", "text/css; charset=utf-8", "application/javascript; charset=utf-8"
      ]).has(asset.contentType)) {
        safeError(response, 404, "approval.not_found", "Approval resource was not found");
        return;
      }
      const bytes = typeof asset.body === "string" ? Buffer.byteLength(asset.body, "utf8") : asset.body.byteLength;
      if (bytes > maxStaticAssetBytes) throw new Error("Static asset is oversized");
      response.status(200).type(asset.contentType).send(asset.body);
    } catch {
      safeError(response, 503, "approval.interface_unavailable", "Approval interface is unavailable");
    }
  });

  app.use("/approval/api", authenticate);
  app.use("/approval/api", requireSameOriginFetch);

  app.post("/approval/api/session", async (request, response) => {
    const principal = principals.get(request);
    if (principal === undefined) throw new Error("Authenticated human principal is unavailable");
    const rawSessionId = opaqueTokenSchema.parse(tokenFactory());
    const rawCsrfToken = opaqueTokenSchema.parse(tokenFactory());
    if (rawSessionId === rawCsrfToken) throw new Error("Session and CSRF tokens must be independent");
    const createdAt = clock();
    try {
      const session = approvalWebSessionV1Schema.parse(await options.store.createSession({
        sessionIdDigest: digest(rawSessionId),
        csrfTokenDigest: digest(rawCsrfToken),
        principal,
        createdAt: createdAt.toISOString(),
        expiresAt: new Date(createdAt.getTime() + sessionLifetimeMs).toISOString()
      }));
      if (session.humanId !== principal.humanId || session.authenticationMethod !== principal.authenticationMethod ||
        session.credentialId !== principal.credentialId || session.identityRevision !== principal.identityRevision ||
        session.sessionIdDigest !== digest(rawSessionId) ||
        !equalDigest(session.csrfTokenDigest, digest(rawCsrfToken))) {
        throw new Error("Session store returned an invalid binding");
      }
      response.setHeader("Set-Cookie", `${cookieName}=${rawSessionId}; Path=/; Secure; HttpOnly; SameSite=Strict`);
      response.status(201).type("application/json").json({
        schemaVersion: "1.0.0",
        csrfToken: rawCsrfToken,
        expiresAt: session.expiresAt,
        human: {
          humanId: session.humanId,
          authenticationMethod: session.authenticationMethod
        }
      });
    } catch {
      safeError(response, 503, "approval.session_unavailable", "Approval session is unavailable");
    }
  });

  app.get("/approval/api/pending", authorizeSession, async (request, response) => {
    const session = sessions.get(request);
    if (session === undefined) throw new Error("Authorized approval session is unavailable");
    try {
      const records = (await options.store.listPending(session)).map((item) => recordForScope(item, session));
      if (records.some((item) => item.approval.state !== "PENDING")) {
        throw new Error("Pending approval query returned non-pending state");
      }
      response.status(200).type("application/json").json({
        schemaVersion: "1.0.0",
        approvals: records.map(listItem)
      });
    } catch {
      safeError(response, 503, "approval.list_unavailable", "Pending approvals are unavailable");
    }
  });

  app.get("/approval/api/approvals/:approvalId", authorizeSession, async (request, response) => {
    const session = sessions.get(request);
    const approvalId = identifierV1Schema.safeParse(request.params["approvalId"]);
    if (session === undefined || !approvalId.success) {
      safeError(response, 404, "approval.not_found", "Approval was not found");
      return;
    }
    try {
      const candidate = await options.store.readApproval(session, approvalId.data);
      if (candidate === null) {
        safeError(response, 404, "approval.not_found", "Approval was not found");
        return;
      }
      const record = recordForScope(candidate, session);
      response.setHeader("ETag", `"${String(record.revision)}"`);
      response.status(200).type("application/json").json(record);
    } catch {
      safeError(response, 503, "approval.detail_unavailable", "Approval detail is unavailable");
    }
  });

  app.post(
    "/approval/api/approvals/:approvalId/decision",
    authorizeSession,
    express.json({ inflate: false, limit: maxJsonBodyBytes, strict: true, type: "application/json" }),
    async (request, response) => {
      const session = sessions.get(request);
      const approvalId = identifierV1Schema.safeParse(request.params["approvalId"]);
      const expectedRevision = parseIfMatch(request);
      const csrfToken = typeof request.headers["x-csrf-token"] === "string"
        ? opaqueTokenSchema.safeParse(request.headers["x-csrf-token"])
        : null;
      const decision = approvalWebDecisionRequestV1Schema.safeParse(request.body);
      if (session === undefined || !approvalId.success) {
        safeError(response, 404, "approval.not_found", "Approval was not found");
        return;
      }
      if (expectedRevision === null || csrfToken === null || !csrfToken.success ||
        !equalDigest(session.csrfTokenDigest, digest(csrfToken.data))) {
        safeError(response, 403, "approval.request_integrity_denied", "Approval request integrity check failed");
        return;
      }
      if (!request.is("application/json") || !decision.success) {
        safeError(response, 400, "approval.invalid_decision", "Approval decision is invalid");
        return;
      }
      try {
        const record = recordForScope(await options.store.decide({
          session,
          approvalId: approvalId.data,
          decision: decision.data.decision,
          expectedRevision,
          decidedAt: clock().toISOString()
        }), session);
        const expectedState = decision.data.decision === "APPROVE" ? "APPROVED" : "DENIED";
        if (record.approval.state !== expectedState || record.approval.decidedByHumanId !== session.humanId ||
          record.revision <= expectedRevision) {
          throw new Error("Decision store returned an invalid transition");
        }
        response.setHeader("ETag", `"${String(record.revision)}"`);
        response.status(200).type("application/json").json(record);
      } catch (error) {
        if (error instanceof ApprovalWebStaleDecisionV1) {
          safeError(response, 409, "approval.stale", "Approval state changed; reload before deciding");
          return;
        }
        safeError(response, 503, "approval.decision_unavailable", "Approval decision is unavailable");
      }
    }
  );

  const errorHandler: ErrorRequestHandler = (error, _request, response, next) => {
    void next;
    const type = typeof error === "object" && error !== null && "type" in error
      ? (error as { type?: unknown }).type
      : null;
    if (type === "entity.too.large") {
      safeError(response, 413, "approval.payload_too_large", "Approval request body exceeds the limit");
      return;
    }
    if (type === "encoding.unsupported") {
      safeError(response, 415, "approval.encoding_unsupported", "Compressed request bodies are not supported");
      return;
    }
    if (error instanceof SyntaxError) {
      safeError(response, 400, "approval.invalid_json", "Approval request body is invalid");
      return;
    }
    safeError(response, 500, "approval.internal_error", "Approval interface failed safely");
  };
  app.use(errorHandler);
  return app;
}

export type {
  ApprovalV1,
  ExecutionOutcomeV1,
  TrustworthyActionInterfaceV1
};
