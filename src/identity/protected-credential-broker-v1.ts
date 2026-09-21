import { createHash, randomUUID } from "node:crypto";

import { z } from "zod";

import { identifierV1Schema, sha256DigestV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema,
  type AuthenticatedSessionIdentityBindingV1
} from "./client-authentication-v1.js";
import {
  credentialProfileV1Schema,
  type CredentialedMcpHttpResponseV1,
  type CredentialProfileV1
} from "./credential-vault-v1.js";

const MAX_LEASE_LIFETIME_MS = 5 * 60 * 1_000;
const MAX_HTTP_BODY_BYTES = 64 * 1_024 * 1_024;

export const approvedSecretManagerDescriptorV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  providerId: identifierV1Schema,
  providerType: z.enum([
    "AZURE_KEY_VAULT",
    "AWS_SECRETS_MANAGER",
    "HASHICORP_VAULT",
    "CUSTOM_APPROVED"
  ]),
  approval: z.object({
    status: z.literal("APPROVED"),
    approvedBy: identifierV1Schema,
    approvedAt: utcTimestampV1Schema,
    configurationDigest: sha256DigestV1Schema
  }).strict()
}).strict();

export const protectedCredentialBindingV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  secretManagerProviderId: identifierV1Schema,
  secretReference: z.string().trim().min(1).max(1_024),
  profile: credentialProfileV1Schema
}).strict();

export const protectedCredentialLeaseV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  leaseId: identifierV1Schema,
  credentialProfileId: identifierV1Schema,
  credentialRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  secretManagerProviderId: identifierV1Schema,
  audienceId: identifierV1Schema,
  routeId: identifierV1Schema,
  approvalId: identifierV1Schema,
  actionHash: sha256DigestV1Schema,
  forwardingAttemptId: identifierV1Schema,
  endpointOrigin: z.url().max(2_048),
  transportSessionId: z.string().min(1).max(128).regex(/^[A-Za-z0-9._~-]+$/u),
  stateNamespace: identifierV1Schema,
  issuedAt: utcTimestampV1Schema,
  expiresAt: utcTimestampV1Schema
}).strict().superRefine((lease, context) => {
  const lifetime = Date.parse(lease.expiresAt) - Date.parse(lease.issuedAt);
  if (lifetime <= 0 || lifetime > MAX_LEASE_LIFETIME_MS) {
    context.addIssue({
      code: "custom",
      path: ["expiresAt"],
      message: "Protected credential leases must expire within five minutes"
    });
  }
  if (new URL(lease.endpointOrigin).origin !== lease.endpointOrigin) {
    context.addIssue({
      code: "custom",
      path: ["endpointOrigin"],
      message: "The lease endpoint must be a canonical origin"
    });
  }
});

export type ApprovedSecretManagerDescriptorV1 = z.infer<
  typeof approvedSecretManagerDescriptorV1Schema
>;
export type ProtectedCredentialBindingV1 = z.infer<
  typeof protectedCredentialBindingV1Schema
>;
export type ProtectedCredentialLeaseV1 = z.infer<typeof protectedCredentialLeaseV1Schema>;

export interface SecretManagerExactRevisionV1 {
  readonly providerId: string;
  readonly secretReference: string;
  readonly credentialProfileId: string;
  readonly credentialRevision: number;
  readonly material: Uint8Array;
}

export interface ApprovedSecretManagerProviderV1 {
  readonly descriptor: ApprovedSecretManagerDescriptorV1;
  fetchExactRevision(input: {
    readonly secretReference: string;
    readonly credentialProfileId: string;
    readonly credentialRevision: number;
    readonly signal?: AbortSignal;
  }): Promise<SecretManagerExactRevisionV1 | null>;
}

export type ProtectedCredentialDenialReasonV1 =
  | "AUDIENCE_MISMATCH"
  | "AUTHORIZATION_MISMATCH"
  | "CANCELLED"
  | "ENDPOINT_MISMATCH"
  | "LEASE_EXPIRED"
  | "LEASE_REPLAYED"
  | "PROFILE_EXPIRED"
  | "PROFILE_UNAVAILABLE"
  | "PROVIDER_UNAVAILABLE"
  | "REVISION_MISMATCH"
  | "ROUTE_MISMATCH"
  | "SESSION_MISMATCH"
  | "UNKNOWN_LEASE";

export class ProtectedCredentialDeniedV1 extends Error {
  public readonly reason: ProtectedCredentialDenialReasonV1;

  public constructor(reason: ProtectedCredentialDenialReasonV1) {
    super("Protected credential access denied");
    this.name = "ProtectedCredentialDeniedV1";
    this.reason = reason;
  }
}

interface StoredLeaseV1 {
  readonly lease: ProtectedCredentialLeaseV1;
  readonly binding: ProtectedCredentialBindingV1;
}

export interface ProtectedCredentialBrokerV1Options {
  readonly secretManager: ApprovedSecretManagerProviderV1;
  readonly bindings: readonly ProtectedCredentialBindingV1[];
  readonly clock?: () => Date;
  readonly leaseIdFactory?: () => string;
  readonly fetchImplementation?: typeof fetch;
}

/**
 * Credential material crosses this boundary only while constructing one exact HTTP
 * request. The broker deliberately exposes no material getter or material-bearing
 * lease and clears every received or copied byte buffer in a finally block.
 */
export class ProtectedCredentialBrokerV1 {
  readonly #secretManager: ApprovedSecretManagerProviderV1;
  readonly #bindings = new Map<string, ProtectedCredentialBindingV1>();
  readonly #leases = new Map<string, StoredLeaseV1>();
  /** Process-local atomic latch; durable multi-process replay denial remains the coordinator's duty. */
  readonly #consumedLeases = new Set<string>();
  readonly #clock: () => Date;
  readonly #leaseIdFactory: () => string;
  readonly #fetch: typeof fetch;

  public constructor(options: ProtectedCredentialBrokerV1Options) {
    const descriptor = approvedSecretManagerDescriptorV1Schema.parse(
      options.secretManager.descriptor
    );
    this.#secretManager = options.secretManager;
    this.#clock = options.clock ?? (() => new Date());
    this.#leaseIdFactory = options.leaseIdFactory ?? randomUUID;
    this.#fetch = options.fetchImplementation ?? fetch;

    for (const bindingInput of options.bindings) {
      const binding = protectedCredentialBindingV1Schema.parse(bindingInput);
      if (binding.secretManagerProviderId !== descriptor.providerId) {
        throw new ProtectedCredentialDeniedV1("PROVIDER_UNAVAILABLE");
      }
      if (this.#bindings.has(binding.profile.credentialProfileId)) {
        throw new Error("Protected credential profile is duplicated");
      }
      this.#bindings.set(binding.profile.credentialProfileId, binding);
    }
  }

  public issueLease(
    sessionInput: AuthenticatedSessionIdentityBindingV1,
    request: {
      readonly credentialProfileId: string;
      readonly audienceId: string;
      readonly routeId: string;
      readonly endpointOrigin: string;
      readonly approvalId: string;
      readonly actionHash: string;
      readonly forwardingAttemptId: string;
    }
  ): ProtectedCredentialLeaseV1 {
    const session = authenticatedSessionIdentityBindingV1Schema.parse(sessionInput);
    const binding = this.#bindings.get(identifierV1Schema.parse(request.credentialProfileId));
    if (binding === undefined || binding.profile.status !== "ACTIVE") {
      throw new ProtectedCredentialDeniedV1("PROFILE_UNAVAILABLE");
    }
    const now = this.#validNow();
    if (now.getTime() >= Date.parse(binding.profile.expiresAt)) {
      throw new ProtectedCredentialDeniedV1("PROFILE_EXPIRED");
    }
    if (binding.profile.audienceId !== request.audienceId) {
      throw new ProtectedCredentialDeniedV1("AUDIENCE_MISMATCH");
    }
    if (!binding.profile.allowedRouteIds.includes(request.routeId)) {
      throw new ProtectedCredentialDeniedV1("ROUTE_MISMATCH");
    }
    const endpointOrigin = new URL(request.endpointOrigin).origin;
    if (endpointOrigin !== request.endpointOrigin ||
      !binding.profile.allowedEndpointOrigins.includes(endpointOrigin)) {
      throw new ProtectedCredentialDeniedV1("ENDPOINT_MISMATCH");
    }
    const lease = protectedCredentialLeaseV1Schema.parse({
      schemaVersion: "1.0.0",
      leaseId: this.#leaseIdFactory(),
      credentialProfileId: binding.profile.credentialProfileId,
      credentialRevision: binding.profile.credentialRevision,
      secretManagerProviderId: binding.secretManagerProviderId,
      audienceId: binding.profile.audienceId,
      routeId: request.routeId,
      approvalId: identifierV1Schema.parse(request.approvalId),
      actionHash: sha256DigestV1Schema.parse(request.actionHash),
      forwardingAttemptId: identifierV1Schema.parse(request.forwardingAttemptId),
      endpointOrigin,
      transportSessionId: session.transportSessionId,
      stateNamespace: session.stateNamespace,
      issuedAt: now.toISOString(),
      expiresAt: new Date(Math.min(
        now.getTime() + MAX_LEASE_LIFETIME_MS,
        Date.parse(binding.profile.expiresAt)
      )).toISOString()
    });
    if (this.#leases.has(lease.leaseId)) {
      throw new Error("Protected credential lease identifier collision");
    }
    this.#leases.set(lease.leaseId, { lease, binding });
    return lease;
  }

  public async sendMcpJsonWithLease(
    sessionInput: AuthenticatedSessionIdentityBindingV1,
    request: {
      readonly leaseId: string;
      readonly credentialProfileId: string;
      readonly credentialRevision?: number;
      readonly audienceId: string;
      readonly routeId: string;
      readonly approvalId: string;
      readonly actionHash: string;
      readonly forwardingAttemptId: string;
      readonly endpoint: string;
      readonly body: Uint8Array;
      readonly maxResponseBytes: number;
      readonly signal?: AbortSignal;
    }
  ): Promise<CredentialedMcpHttpResponseV1> {
    const session = authenticatedSessionIdentityBindingV1Schema.parse(sessionInput);
    this.#throwIfCancelled(request.signal);
    const stored = this.#leases.get(identifierV1Schema.parse(request.leaseId));
    if (stored === undefined) throw new ProtectedCredentialDeniedV1("UNKNOWN_LEASE");
    const { lease, binding } = stored;
    if (lease.transportSessionId !== session.transportSessionId ||
      lease.stateNamespace !== session.stateNamespace) {
      throw new ProtectedCredentialDeniedV1("SESSION_MISMATCH");
    }
    if (lease.credentialProfileId !== request.credentialProfileId ||
      (request.credentialRevision !== undefined &&
        lease.credentialRevision !== request.credentialRevision)) {
      throw new ProtectedCredentialDeniedV1("REVISION_MISMATCH");
    }
    if (lease.audienceId !== request.audienceId) {
      throw new ProtectedCredentialDeniedV1("AUDIENCE_MISMATCH");
    }
    if (lease.routeId !== request.routeId) {
      throw new ProtectedCredentialDeniedV1("ROUTE_MISMATCH");
    }
    if (lease.approvalId !== request.approvalId || lease.actionHash !== request.actionHash ||
      lease.forwardingAttemptId !== request.forwardingAttemptId) {
      throw new ProtectedCredentialDeniedV1("AUTHORIZATION_MISMATCH");
    }
    const now = this.#validNow();
    if (now.getTime() >= Date.parse(lease.expiresAt)) {
      throw new ProtectedCredentialDeniedV1("LEASE_EXPIRED");
    }
    const endpoint = new URL(request.endpoint);
    if (endpoint.origin !== lease.endpointOrigin) {
      throw new ProtectedCredentialDeniedV1("ENDPOINT_MISMATCH");
    }
    if (!Number.isSafeInteger(request.maxResponseBytes) || request.maxResponseBytes <= 0 ||
      request.maxResponseBytes > MAX_HTTP_BODY_BYTES || request.body.byteLength > MAX_HTTP_BODY_BYTES) {
      throw new RangeError("Protected credential HTTP byte limit is invalid");
    }

    // This synchronous check-and-add occurs before provider or network I/O. Node cannot
    // interleave another use in this section, so one broker instance consumes once.
    if (this.#consumedLeases.has(lease.leaseId)) {
      throw new ProtectedCredentialDeniedV1("LEASE_REPLAYED");
    }
    this.#consumedLeases.add(lease.leaseId);

    let providerMaterial: Uint8Array | undefined;
    let materialCopy: Buffer | undefined;
    try {
      let secret: SecretManagerExactRevisionV1 | null;
      try {
        secret = await this.#secretManager.fetchExactRevision({
          secretReference: binding.secretReference,
          credentialProfileId: lease.credentialProfileId,
          credentialRevision: lease.credentialRevision,
          ...(request.signal === undefined ? {} : { signal: request.signal })
        });
      } catch {
        this.#throwIfCancelled(request.signal);
        throw new ProtectedCredentialDeniedV1("PROVIDER_UNAVAILABLE");
      }
      this.#throwIfCancelled(request.signal);
      if (secret === null) throw new ProtectedCredentialDeniedV1("PROFILE_UNAVAILABLE");
      providerMaterial = secret.material;
      if (secret.providerId !== lease.secretManagerProviderId ||
        secret.secretReference !== binding.secretReference) {
        throw new ProtectedCredentialDeniedV1("PROVIDER_UNAVAILABLE");
      }
      if (secret.credentialProfileId !== lease.credentialProfileId ||
        secret.credentialRevision !== lease.credentialRevision) {
        throw new ProtectedCredentialDeniedV1("REVISION_MISMATCH");
      }
      if (!(secret.material instanceof Uint8Array) ||
        secret.material.byteLength < 16 || secret.material.byteLength > 16_384) {
        throw new ProtectedCredentialDeniedV1("PROFILE_UNAVAILABLE");
      }
      materialCopy = Buffer.from(secret.material);
      if (createHash("sha256").update(materialCopy).digest("hex") !==
        binding.profile.materialDigest) {
        throw new ProtectedCredentialDeniedV1("REVISION_MISMATCH");
      }

      const credential = materialCopy.toString("utf8");
      const credentialHeader = binding.profile.credentialKind === "BEARER_TOKEN"
        ? { Authorization: `Bearer ${credential}` }
        : binding.profile.credentialKind === "API_KEY"
          ? { "X-MCP-API-Key": credential }
          : undefined;
      if (credentialHeader === undefined) {
        throw new ProtectedCredentialDeniedV1("PROFILE_UNAVAILABLE");
      }
      const response = await this.#fetch(endpoint, {
        method: "POST",
        redirect: "manual",
        headers: { "Content-Type": "application/json", Accept: "application/json", ...credentialHeader },
        body: Buffer.from(request.body),
        ...(request.signal === undefined ? {} : { signal: request.signal })
      });
      if (response.status >= 300 && response.status < 400) {
        await response.body?.cancel();
        throw new ProtectedCredentialDeniedV1("ENDPOINT_MISMATCH");
      }
      const responseBody = await this.#readBoundedResponse(response, request.maxResponseBytes);
      return Object.freeze({
        status: response.status,
        contentType: response.headers.get("content-type"),
        downstreamAuthentication: response.headers.get("mcp-server-authorization") ?? undefined,
        body: responseBody
      });
    } finally {
      materialCopy?.fill(0);
      providerMaterial?.fill(0);
    }
  }

  #validNow(): Date {
    const now = this.#clock();
    if (!Number.isFinite(now.getTime())) {
      throw new ProtectedCredentialDeniedV1("PROVIDER_UNAVAILABLE");
    }
    return now;
  }

  async #readBoundedResponse(response: Response, maximum: number): Promise<Uint8Array> {
    const lengthHeader = response.headers.get("content-length");
    if (lengthHeader !== null) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(lengthHeader)) {
        await response.body?.cancel();
        throw new RangeError("Downstream response Content-Length is invalid");
      }
      const declared = Number(lengthHeader);
      if (!Number.isSafeInteger(declared) || declared > maximum) {
        await response.body?.cancel();
        throw new RangeError("Downstream response exceeds the result limit");
      }
    }
    if (response.body === null) return new Uint8Array();
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    let complete = false;
    try {
      while (!complete) {
        const item = await reader.read();
        if (item.done) {
          complete = true;
          continue;
        }
        received += item.value.byteLength;
        if (received > maximum) {
          await reader.cancel();
          throw new RangeError("Downstream response exceeds the result limit");
        }
        chunks.push(item.value);
      }
    } finally {
      reader.releaseLock();
    }
    const body = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return body;
  }

  #throwIfCancelled(signal: AbortSignal | undefined): void {
    if (signal?.aborted === true) throw new ProtectedCredentialDeniedV1("CANCELLED");
  }
}

export type { CredentialProfileV1 };
