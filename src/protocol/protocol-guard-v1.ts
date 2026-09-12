import { createHash, randomUUID } from "node:crypto";

import { z } from "zod";

import {
  capabilityIdentifierV1Schema,
  identifierV1Schema,
  utcTimestampV1Schema
} from "../contracts/v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema
} from "../identity/client-authentication-v1.js";

const MAX_SAFE_DURATION_MS = 5 * 60 * 1_000;

export const protocolGuardLimitsV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    maxClockSkewMs: z.number().int().positive().max(MAX_SAFE_DURATION_MS),
    replayTtlMs: z.number().int().positive().max(60 * 60 * 1_000),
    rateWindowMs: z.number().int().positive().max(60 * 60 * 1_000),
    callsPerWindow: z.number().int().positive().max(100_000),
    concurrentCalls: z.number().int().positive().max(1_000),
    payloadBytes: z.number().int().positive().max(64 * 1024 * 1024),
    resultBytes: z.number().int().positive().max(64 * 1024 * 1024),
    callDepth: z.number().int().nonnegative().max(64),
    delegationDepth: z.number().int().nonnegative().max(32),
    fanOut: z.number().int().nonnegative().max(1_000),
    redirects: z.number().int().nonnegative().max(32),
    retries: z.number().int().nonnegative().max(32),
    executionMs: z.number().int().positive().max(MAX_SAFE_DURATION_MS),
    circuitFailureThreshold: z.number().int().positive().max(100)
  })
  .strict();

const ancestryEntryV1Schema = z
  .object({
    requestId: identifierV1Schema,
    routeId: identifierV1Schema,
    destinationId: identifierV1Schema,
    actionFamily: capabilityIdentifierV1Schema
  })
  .strict();

export const protocolOperationRequestV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    requestId: identifierV1Schema,
    nonce: identifierV1Schema,
    requestedAt: utcTimestampV1Schema,
    session: authenticatedSessionIdentityBindingV1Schema,
    serverId: identifierV1Schema,
    toolName: capabilityIdentifierV1Schema,
    routeId: identifierV1Schema,
    destinationId: identifierV1Schema,
    actionFamily: capabilityIdentifierV1Schema,
    callChain: z
      .object({
        callChainId: identifierV1Schema,
        parentRequestId: identifierV1Schema.nullable(),
        depth: z.number().int().nonnegative().max(64),
        delegationDepth: z.number().int().nonnegative().max(32),
        ancestry: z.array(ancestryEntryV1Schema).max(64)
      })
      .strict(),
    payloadBytes: z.number().int().nonnegative().max(64 * 1024 * 1024),
    expectedResultBytes: z.number().int().nonnegative().max(64 * 1024 * 1024),
    fanOut: z.number().int().nonnegative().max(1_000),
    redirectCount: z.number().int().nonnegative().max(32),
    retryCount: z.number().int().nonnegative().max(32),
    mutation: z.boolean(),
    requiredDependencies: z.array(capabilityIdentifierV1Schema).max(32)
  })
  .strict()
  .superRefine((request, context) => {
    if (request.callChain.depth !== request.callChain.ancestry.length) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "depth"],
        message: "Call depth must equal the recorded ancestry length"
      });
    }
    if (request.callChain.delegationDepth > request.callChain.depth) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "delegationDepth"],
        message: "Delegation depth cannot exceed call depth"
      });
    }
    const expectedParent = request.callChain.ancestry.at(-1)?.requestId ?? null;
    if (request.callChain.parentRequestId !== expectedParent) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "parentRequestId"],
        message: "Parent request must be the final ancestry entry"
      });
    }
    if (new Set(request.callChain.ancestry.map((entry) => entry.requestId)).size !==
      request.callChain.ancestry.length) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "ancestry"],
        message: "Call ancestry cannot contain repeated requests"
      });
    }
    if (new Set(request.requiredDependencies).size !== request.requiredDependencies.length) {
      context.addIssue({
        code: "custom",
        path: ["requiredDependencies"],
        message: "Required dependencies must be unique"
      });
    }
  });

export const protocolGuardAuditEventV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    eventId: identifierV1Schema,
    eventType: z.enum([
      "ADMITTED",
      "COMPLETED",
      "OPERATION_FAILED",
      "REPLAY_DENIED",
      "FRESHNESS_DENIED",
      "QUOTA_DENIED",
      "BOUND_DENIED",
      "RECURSION_DENIED",
      "CANCELLED",
      "TIMED_OUT",
      "CIRCUIT_OPENED",
      "DEPENDENCY_DENIED"
    ]),
    requestId: identifierV1Schema.nullable(),
    sessionNamespace: identifierV1Schema.nullable(),
    serverId: identifierV1Schema.nullable(),
    routeId: identifierV1Schema.nullable(),
    dependencyId: capabilityIdentifierV1Schema.nullable(),
    quotaDimension: z.enum([
      "SESSION", "USER", "AGENT", "CLIENT", "SERVER", "TOOL", "ROUTE",
      "DESTINATION", "ACTION_FAMILY"
    ]).nullable(),
    reasonCode: capabilityIdentifierV1Schema,
    evidenceDigest: z.string().regex(/^[a-f0-9]{64}$/u),
    occurredAt: utcTimestampV1Schema
  })
  .strict();

export type ProtocolGuardLimitsV1 = z.infer<typeof protocolGuardLimitsV1Schema>;
export type ProtocolOperationRequestV1 = z.infer<typeof protocolOperationRequestV1Schema>;
export type ProtocolGuardAuditEventV1 = z.infer<typeof protocolGuardAuditEventV1Schema>;

export type ProtocolGuardDenialReasonV1 =
  | "BOUND_EXCEEDED"
  | "CANCELLED"
  | "DEPENDENCY_UNAVAILABLE"
  | "QUOTA_EXCEEDED"
  | "RECURSION_DETECTED"
  | "REPLAY_DETECTED"
  | "TIMED_OUT"
  | "TIMESTAMP_OUT_OF_RANGE";

export class ProtocolGuardDeniedV1 extends Error {
  public readonly reason: ProtocolGuardDenialReasonV1;
  public readonly quotaDimension: string | null;

  public constructor(reason: ProtocolGuardDenialReasonV1, quotaDimension: string | null = null) {
    super("Protocol operation denied");
    this.name = "ProtocolGuardDeniedV1";
    this.reason = reason;
    this.quotaDimension = quotaDimension;
  }
}

export interface ProtocolOperationLeaseV1 {
  readonly operationId: string;
  readonly requestId: string;
  readonly deadlineAt: string;
}

export interface ProtocolOperationCheckpointV1 {
  readonly additionalFanOut?: number;
  readonly additionalRedirects?: number;
  readonly additionalRetries?: number;
  readonly observedResultBytes?: number;
}

export interface GuardedOperationToolsV1 {
  readonly signal: AbortSignal;
  checkpoint(checkpoint: ProtocolOperationCheckpointV1): void;
}

export interface GuardedOperationResultV1<T> {
  readonly value: T;
  readonly resultBytes: number;
}

export interface DisposableProtocolGuardV1Options {
  readonly limits: ProtocolGuardLimitsV1;
  readonly clock?: () => Date;
  readonly operationIdFactory?: () => string;
  readonly eventIdFactory?: () => string;
}

interface ActiveOperationV1 {
  readonly request: ProtocolOperationRequestV1;
  readonly concurrencyKeys: readonly string[];
  fanOut: number;
  redirects: number;
  retries: number;
  maxObservedResultBytes: number;
}

interface DependencyStateV1 {
  failures: number;
  state: "CLOSED" | "DEGRADED" | "OPEN";
}

function stableDigest(value: unknown): string {
  const serialize = (entry: unknown): string => {
    if (Array.isArray(entry)) {
      return `[${entry.map((item) => serialize(item)).join(",")}]`;
    }
    if (entry !== null && typeof entry === "object") {
      return `{${Object.entries(entry)
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([key, item]) => `${JSON.stringify(key)}:${serialize(item)}`)
        .join(",")}}`;
    }
    return JSON.stringify(entry);
  };
  return createHash("sha256").update(serialize(value), "utf8").digest("hex");
}

/** Disposable process-local protocol guard for automated tests only. */
export class DisposableProtocolGuardV1 {
  readonly #limits: ProtocolGuardLimitsV1;
  readonly #clock: () => Date;
  readonly #operationIdFactory: () => string;
  readonly #eventIdFactory: () => string;
  readonly #replayEntries = new Map<string, number>();
  readonly #rateEntries = new Map<string, number[]>();
  readonly #concurrency = new Map<string, number>();
  readonly #active = new Map<string, ActiveOperationV1>();
  readonly #dependencies = new Map<string, DependencyStateV1>();
  readonly #audit: ProtocolGuardAuditEventV1[] = [];

  public constructor(options: DisposableProtocolGuardV1Options) {
    this.#limits = protocolGuardLimitsV1Schema.parse(options.limits);
    this.#clock = options.clock ?? (() => new Date());
    this.#operationIdFactory = options.operationIdFactory ?? randomUUID;
    this.#eventIdFactory = options.eventIdFactory ?? randomUUID;
  }

  public begin(requestInput: ProtocolOperationRequestV1): ProtocolOperationLeaseV1 {
    const request = protocolOperationRequestV1Schema.parse(requestInput);
    const now = this.#clock();
    const nowMs = now.getTime();
    if (Math.abs(nowMs - Date.parse(request.requestedAt)) > this.#limits.maxClockSkewMs) {
      this.#deny("FRESHNESS_DENIED", "TIMESTAMP_OUT_OF_RANGE", request);
    }
    this.#pruneReplay(nowMs);
    const replayKeys = [
      `request:${request.session.stateNamespace}:${request.requestId}`,
      `nonce:${request.session.stateNamespace}:${request.nonce}`
    ];
    if (replayKeys.some((key) => this.#replayEntries.has(key))) {
      this.#deny("REPLAY_DENIED", "REPLAY_DETECTED", request);
    }
    for (const key of replayKeys) {
      this.#replayEntries.set(key, nowMs + this.#limits.replayTtlMs);
    }

    this.#assertBounds(request);
    this.#assertNoRecursion(request);
    for (const dependencyId of request.requiredDependencies) {
      if (this.#dependencies.get(dependencyId)?.state !== "CLOSED") {
        this.#deny("DEPENDENCY_DENIED", "DEPENDENCY_UNAVAILABLE", request, dependencyId);
      }
    }

    const dimensionKeys = this.#dimensionKeys(request);
    const windowStart = nowMs - this.#limits.rateWindowMs;
    for (const [index, key] of dimensionKeys.entries()) {
      const current = (this.#rateEntries.get(key) ?? []).filter(
        (timestamp) => timestamp > windowStart
      );
      this.#rateEntries.set(key, current);
      if (current.length >= this.#limits.callsPerWindow ||
        (this.#concurrency.get(key) ?? 0) >= this.#limits.concurrentCalls) {
        const quotaDimensions = [
          "SESSION", "USER", "AGENT", "CLIENT", "SERVER", "TOOL", "ROUTE",
          "DESTINATION", "ACTION_FAMILY"
        ] as const;
        this.#deny("QUOTA_DENIED", "QUOTA_EXCEEDED", request, null,
          quotaDimensions[index] ?? null);
      }
    }
    for (const key of dimensionKeys) {
      this.#rateEntries.get(key)?.push(nowMs);
      this.#concurrency.set(key, (this.#concurrency.get(key) ?? 0) + 1);
    }

    const operationId = identifierV1Schema.parse(this.#operationIdFactory());
    if (this.#active.has(operationId)) {
      for (const key of dimensionKeys) {
        this.#concurrency.set(key, Math.max(0, (this.#concurrency.get(key) ?? 1) - 1));
      }
      throw new Error("Protocol operation identifier collision");
    }
    this.#active.set(operationId, {
      request,
      concurrencyKeys: dimensionKeys,
      fanOut: request.fanOut,
      redirects: request.redirectCount,
      retries: request.retryCount,
      maxObservedResultBytes: 0
    });
    this.#record("ADMITTED", "protocol.admitted", request, null);
    return Object.freeze({
      operationId,
      requestId: request.requestId,
      deadlineAt: new Date(nowMs + this.#limits.executionMs).toISOString()
    });
  }

  public checkpoint(operationId: string, checkpoint: ProtocolOperationCheckpointV1): void {
    const active = this.#activeOperation(operationId);
    let fanOut: number;
    let redirects: number;
    let retries: number;
    try {
      fanOut = active.fanOut + this.#nonnegativeIncrement(checkpoint.additionalFanOut);
      redirects = active.redirects + this.#nonnegativeIncrement(
        checkpoint.additionalRedirects
      );
      retries = active.retries + this.#nonnegativeIncrement(checkpoint.additionalRetries);
    } catch {
      this.#record("BOUND_DENIED", "protocol.invalid_checkpoint", active.request, null);
      this.#release(operationId);
      throw new ProtocolGuardDeniedV1("BOUND_EXCEEDED");
    }
    const resultBytes = checkpoint.observedResultBytes ?? active.maxObservedResultBytes;
    if (!Number.isSafeInteger(resultBytes) || resultBytes < 0 ||
      fanOut > this.#limits.fanOut || redirects > this.#limits.redirects ||
      retries > this.#limits.retries || resultBytes > this.#limits.resultBytes) {
      this.#record("BOUND_DENIED", "protocol.bound_exceeded", active.request, null);
      this.#release(operationId);
      throw new ProtocolGuardDeniedV1("BOUND_EXCEEDED");
    }
    active.fanOut = fanOut;
    active.redirects = redirects;
    active.retries = retries;
    active.maxObservedResultBytes = Math.max(active.maxObservedResultBytes, resultBytes);
  }

  public complete(operationId: string, resultBytes: number): void {
    const active = this.#activeOperation(operationId);
    if (!Number.isSafeInteger(resultBytes) || resultBytes < 0 ||
      resultBytes > this.#limits.resultBytes ||
      resultBytes > active.request.expectedResultBytes) {
      this.#record("BOUND_DENIED", "protocol.result_bound_exceeded", active.request, null);
      this.#release(operationId);
      throw new ProtocolGuardDeniedV1("BOUND_EXCEEDED");
    }
    this.#record("COMPLETED", "protocol.completed", active.request, null);
    this.#release(operationId);
  }

  public cancel(operationId: string): void {
    const active = this.#activeOperation(operationId);
    this.#record("CANCELLED", "protocol.cancelled", active.request, null);
    this.#release(operationId);
  }

  public recordDependencyFailure(dependencyIdInput: string): void {
    const dependencyId = capabilityIdentifierV1Schema.parse(dependencyIdInput);
    const current = this.#dependencies.get(dependencyId) ?? { failures: 0, state: "CLOSED" };
    current.failures += 1;
    current.state = current.failures >= this.#limits.circuitFailureThreshold
      ? "OPEN"
      : "DEGRADED";
    this.#dependencies.set(dependencyId, current);
    if (current.state === "OPEN") {
      this.#record("CIRCUIT_OPENED", "dependency.circuit_open", null, dependencyId);
    }
  }

  public recordDependencySuccess(dependencyIdInput: string): void {
    const dependencyId = capabilityIdentifierV1Schema.parse(dependencyIdInput);
    this.#dependencies.set(dependencyId, { failures: 0, state: "CLOSED" });
  }

  public readAudit(): readonly ProtocolGuardAuditEventV1[] {
    return structuredClone(this.#audit);
  }

  public async run<T>(
    request: ProtocolOperationRequestV1,
    operation: (tools: GuardedOperationToolsV1) => Promise<GuardedOperationResultV1<T>>,
    cancellationSignal?: AbortSignal
  ): Promise<T> {
    const lease = this.begin(request);
    const controller = new AbortController();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let cancellationHandler: (() => void) | undefined;
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(() => {
        controller.abort(new ProtocolGuardDeniedV1("TIMED_OUT"));
        reject(new ProtocolGuardDeniedV1("TIMED_OUT"));
      }, this.#limits.executionMs);
    });
    const cancellationPromise = new Promise<never>((_resolve, reject) => {
      cancellationHandler = () => {
        controller.abort(new ProtocolGuardDeniedV1("CANCELLED"));
        reject(new ProtocolGuardDeniedV1("CANCELLED"));
      };
      if (cancellationSignal?.aborted === true) {
        cancellationHandler();
      } else {
        cancellationSignal?.addEventListener("abort", cancellationHandler, { once: true });
      }
    });
    try {
      const result = await Promise.race([
        operation({
          signal: controller.signal,
          checkpoint: (checkpoint) => {
            this.checkpoint(lease.operationId, checkpoint);
          }
        }),
        timeoutPromise,
        cancellationPromise
      ]);
      this.complete(lease.operationId, result.resultBytes);
      return result.value;
    } catch (error) {
      if (this.#active.has(lease.operationId)) {
        const active = this.#activeOperation(lease.operationId);
        if (error instanceof ProtocolGuardDeniedV1 && error.reason === "TIMED_OUT") {
          this.#record("TIMED_OUT", "protocol.timed_out", active.request, null);
        } else if (error instanceof ProtocolGuardDeniedV1 && error.reason === "CANCELLED") {
          this.#record("CANCELLED", "protocol.cancelled", active.request, null);
        } else {
          this.#record("OPERATION_FAILED", "protocol.operation_failed", active.request, null);
        }
        this.#release(lease.operationId);
      }
      throw error;
    } finally {
      if (timeout !== undefined) {
        clearTimeout(timeout);
      }
      if (cancellationHandler !== undefined) {
        cancellationSignal?.removeEventListener("abort", cancellationHandler);
      }
    }
  }

  #assertBounds(request: ProtocolOperationRequestV1): void {
    if (
      request.payloadBytes > this.#limits.payloadBytes ||
      request.expectedResultBytes > this.#limits.resultBytes ||
      request.callChain.depth > this.#limits.callDepth ||
      request.callChain.delegationDepth > this.#limits.delegationDepth ||
      request.fanOut > this.#limits.fanOut ||
      request.redirectCount > this.#limits.redirects ||
      request.retryCount > this.#limits.retries
    ) {
      this.#deny("BOUND_DENIED", "BOUND_EXCEEDED", request);
    }
  }

  #assertNoRecursion(request: ProtocolOperationRequestV1): void {
    const recursive = request.callChain.ancestry.some((entry) =>
      entry.requestId === request.requestId ||
      (entry.routeId === request.routeId &&
        entry.destinationId === request.destinationId &&
        entry.actionFamily === request.actionFamily)
    );
    if (recursive) {
      this.#deny("RECURSION_DENIED", "RECURSION_DETECTED", request);
    }
  }

  #dimensionKeys(request: ProtocolOperationRequestV1): readonly string[] {
    return [
      `session:${request.session.stateNamespace}`,
      `user:${request.session.identity.userId}`,
      `agent:${request.session.identity.agentId}`,
      `client:${request.session.identity.clientId}`,
      `server:${request.serverId}`,
      `tool:${request.toolName}`,
      `route:${request.routeId}`,
      `destination:${request.destinationId}`,
      `action:${request.actionFamily}`
    ];
  }

  #nonnegativeIncrement(value: number | undefined): number {
    const selected = value ?? 0;
    if (!Number.isSafeInteger(selected) || selected < 0) {
      throw new RangeError("Protocol checkpoint increments must be nonnegative integers");
    }
    return selected;
  }

  #activeOperation(operationIdInput: string): ActiveOperationV1 {
    const operationId = identifierV1Schema.parse(operationIdInput);
    const active = this.#active.get(operationId);
    if (active === undefined) {
      throw new ProtocolGuardDeniedV1("REPLAY_DETECTED");
    }
    return active;
  }

  #release(operationId: string): void {
    const active = this.#active.get(operationId);
    if (active === undefined) {
      return;
    }
    for (const key of active.concurrencyKeys) {
      const remaining = Math.max(0, (this.#concurrency.get(key) ?? 1) - 1);
      if (remaining === 0) {
        this.#concurrency.delete(key);
      } else {
        this.#concurrency.set(key, remaining);
      }
    }
    this.#active.delete(operationId);
  }

  #pruneReplay(nowMs: number): void {
    for (const [key, expiresAt] of this.#replayEntries) {
      if (expiresAt <= nowMs) {
        this.#replayEntries.delete(key);
      }
    }
  }

  #deny(
    eventType: ProtocolGuardAuditEventV1["eventType"],
    reason: ProtocolGuardDenialReasonV1,
    request: ProtocolOperationRequestV1,
    dependencyId: string | null = null,
    quotaDimension: string | null = null
  ): never {
    this.#record(eventType, `protocol.${reason.toLowerCase()}`, request, dependencyId,
      quotaDimension);
    throw new ProtocolGuardDeniedV1(reason, quotaDimension);
  }

  #record(
    eventType: ProtocolGuardAuditEventV1["eventType"],
    reasonCode: string,
    request: ProtocolOperationRequestV1 | null,
    dependencyId: string | null,
    quotaDimension: string | null = null
  ): void {
    this.#audit.push(protocolGuardAuditEventV1Schema.parse({
      schemaVersion: "1.0.0",
      eventId: this.#eventIdFactory(),
      eventType,
      requestId: request?.requestId ?? null,
      sessionNamespace: request?.session.stateNamespace ?? null,
      serverId: request?.serverId ?? null,
      routeId: request?.routeId ?? null,
      dependencyId,
      quotaDimension,
      reasonCode,
      evidenceDigest: stableDigest(request === null ? { dependencyId } : {
        requestId: request.requestId,
        nonce: request.nonce,
        sessionNamespace: request.session.stateNamespace,
        serverId: request.serverId,
        routeId: request.routeId,
        destinationId: request.destinationId,
        actionFamily: request.actionFamily,
        requestedAt: request.requestedAt
      }),
      occurredAt: this.#clock().toISOString()
    }));
  }
}
