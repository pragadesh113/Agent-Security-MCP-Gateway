import { createHash, randomUUID } from "node:crypto";

import { z } from "zod";

import {
  identifierV1Schema,
  sha256DigestV1Schema,
  utcTimestampV1Schema
} from "../contracts/v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema,
  type AuthenticatedSessionIdentityBindingV1
} from "./client-authentication-v1.js";

const MAX_PROFILE_LIFETIME_MS = 60 * 60 * 1_000;
const MAX_LEASE_LIFETIME_MS = 5 * 60 * 1_000;

const uniqueRouteIdsV1Schema = z
  .array(identifierV1Schema)
  .min(1)
  .max(1_000)
  .superRefine((routeIds, context) => {
    if (new Set(routeIds).size !== routeIds.length) {
      context.addIssue({ code: "custom", message: "Credential route IDs must be unique" });
    }
  });

export const credentialProfileV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    credentialProfileId: identifierV1Schema,
    credentialRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    credentialKind: z.enum(["BEARER_TOKEN", "API_KEY", "CLIENT_CERTIFICATE"]),
    audienceId: identifierV1Schema,
    allowedRouteIds: uniqueRouteIdsV1Schema,
    allowedEndpointOrigins: z.array(z.url().max(2_048)).min(1).max(32)
      .superRefine((origins, context) => {
        if (new Set(origins).size !== origins.length ||
          origins.some((origin) => new URL(origin).origin !== origin)) {
          context.addIssue({
            code: "custom",
            message: "Credential endpoint origins must be unique canonical origins"
          });
        }
      }),
    materialDigest: sha256DigestV1Schema,
    status: z.enum(["ACTIVE", "REVOKED", "QUARANTINED"]),
    issuedAt: utcTimestampV1Schema,
    expiresAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((profile, context) => {
    const lifetime = Date.parse(profile.expiresAt) - Date.parse(profile.issuedAt);
    if (lifetime <= 0 || lifetime > MAX_PROFILE_LIFETIME_MS) {
      context.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "Credential profiles must expire within one hour of issuance"
      });
    }
  });

export const credentialLeaseV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    leaseId: identifierV1Schema,
    credentialProfileId: identifierV1Schema,
    credentialRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    audienceId: identifierV1Schema,
    routeId: identifierV1Schema,
    transportSessionId: z.string().min(1).max(128).regex(/^[A-Za-z0-9._~-]+$/u),
    stateNamespace: identifierV1Schema,
    issuedAt: utcTimestampV1Schema,
    expiresAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((lease, context) => {
    const lifetime = Date.parse(lease.expiresAt) - Date.parse(lease.issuedAt);
    if (lifetime <= 0 || lifetime > MAX_LEASE_LIFETIME_MS) {
      context.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "Credential leases must expire within five minutes of issuance"
      });
    }
  });

export type CredentialProfileV1 = z.infer<typeof credentialProfileV1Schema>;
export type CredentialLeaseV1 = z.infer<typeof credentialLeaseV1Schema>;

export interface CredentialedMcpHttpResponseV1 {
  readonly status: number;
  readonly contentType: string | null;
  readonly downstreamAuthentication: string | undefined;
  readonly body: Uint8Array;
}

export type CredentialAccessDenialReasonV1 =
  | "AUDIENCE_MISMATCH"
  | "LEASE_EXPIRED"
  | "LEASE_REVOKED"
  | "PROFILE_EXPIRED"
  | "PROFILE_UNAVAILABLE"
  | "ROUTE_MISMATCH"
  | "SESSION_MISMATCH"
  | "UNKNOWN_LEASE"
  | "UNKNOWN_PROFILE";

export class CredentialAccessDeniedV1 extends Error {
  public readonly reason: CredentialAccessDenialReasonV1;

  public constructor(reason: CredentialAccessDenialReasonV1) {
    super("Credential access denied");
    this.name = "CredentialAccessDeniedV1";
    this.reason = reason;
  }
}

interface StoredCredentialProfileV1 {
  readonly metadata: CredentialProfileV1;
  readonly material: Buffer;
}

interface StoredCredentialLeaseV1 {
  readonly lease: CredentialLeaseV1;
  revoked: boolean;
}

export interface DisposableCredentialVaultV1Options {
  readonly clock?: () => Date;
  readonly leaseIdFactory?: () => string;
}

/**
 * Disposable in-memory credential holder for automated tests only.
 *
 * It deliberately exposes no method that returns credential material. A later
 * forwarding adapter may consume it only through a separate trusted sink boundary.
 */
export class DisposableCredentialVaultV1 {
  readonly #clock: () => Date;
  readonly #leaseIdFactory: () => string;
  readonly #profiles = new Map<string, StoredCredentialProfileV1>();
  readonly #leases = new Map<string, StoredCredentialLeaseV1>();

  public constructor(options: DisposableCredentialVaultV1Options = {}) {
    this.#clock = options.clock ?? (() => new Date());
    this.#leaseIdFactory = options.leaseIdFactory ?? randomUUID;
  }

  public registerCredential(
    profileInput: CredentialProfileV1,
    credentialMaterial: Uint8Array
  ): void {
    const profile = credentialProfileV1Schema.parse(profileInput);
    if (credentialMaterial.byteLength < 16 || credentialMaterial.byteLength > 16_384) {
      throw new RangeError("Credential material must contain 16 through 16384 bytes");
    }
    const observedDigest = createHash("sha256").update(credentialMaterial).digest("hex");
    if (observedDigest !== profile.materialDigest) {
      throw new Error("Credential material digest does not match its profile");
    }
    if (this.#profiles.has(profile.credentialProfileId)) {
      throw new Error("Credential profile already exists");
    }

    this.#profiles.set(profile.credentialProfileId, {
      metadata: profile,
      material: Buffer.from(credentialMaterial)
    });
  }

  public issueLease(
    bindingInput: AuthenticatedSessionIdentityBindingV1,
    request: {
      readonly credentialProfileId: string;
      readonly audienceId: string;
      readonly routeId: string;
    }
  ): CredentialLeaseV1 {
    const binding = authenticatedSessionIdentityBindingV1Schema.parse(bindingInput);
    const profile = this.#profiles.get(request.credentialProfileId);
    if (profile === undefined) {
      throw new CredentialAccessDeniedV1("UNKNOWN_PROFILE");
    }
    if (profile.metadata.status !== "ACTIVE") {
      throw new CredentialAccessDeniedV1("PROFILE_UNAVAILABLE");
    }

    const now = this.#clock();
    if (now.getTime() >= Date.parse(profile.metadata.expiresAt)) {
      throw new CredentialAccessDeniedV1("PROFILE_EXPIRED");
    }
    if (request.audienceId !== profile.metadata.audienceId) {
      throw new CredentialAccessDeniedV1("AUDIENCE_MISMATCH");
    }
    if (!profile.metadata.allowedRouteIds.includes(request.routeId)) {
      throw new CredentialAccessDeniedV1("ROUTE_MISMATCH");
    }

    const expiresAt = new Date(
      Math.min(
        now.getTime() + MAX_LEASE_LIFETIME_MS,
        Date.parse(profile.metadata.expiresAt)
      )
    );
    const lease = credentialLeaseV1Schema.parse({
      schemaVersion: "1.0.0",
      leaseId: this.#leaseIdFactory(),
      credentialProfileId: profile.metadata.credentialProfileId,
      credentialRevision: profile.metadata.credentialRevision,
      audienceId: profile.metadata.audienceId,
      routeId: request.routeId,
      transportSessionId: binding.transportSessionId,
      stateNamespace: binding.stateNamespace,
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString()
    });
    if (this.#leases.has(lease.leaseId)) {
      throw new Error("Credential lease identifier collision");
    }
    this.#leases.set(lease.leaseId, { lease, revoked: false });
    return lease;
  }

  public validateLease(
    bindingInput: AuthenticatedSessionIdentityBindingV1,
    request: {
      readonly leaseId: string;
      readonly audienceId: string;
      readonly routeId: string;
    }
  ): CredentialLeaseV1 {
    const binding = authenticatedSessionIdentityBindingV1Schema.parse(bindingInput);
    const stored = this.#leases.get(request.leaseId);
    if (stored === undefined) {
      throw new CredentialAccessDeniedV1("UNKNOWN_LEASE");
    }
    if (stored.revoked) {
      throw new CredentialAccessDeniedV1("LEASE_REVOKED");
    }
    if (
      stored.lease.transportSessionId !== binding.transportSessionId ||
      stored.lease.stateNamespace !== binding.stateNamespace
    ) {
      throw new CredentialAccessDeniedV1("SESSION_MISMATCH");
    }
    if (stored.lease.audienceId !== request.audienceId) {
      throw new CredentialAccessDeniedV1("AUDIENCE_MISMATCH");
    }
    if (stored.lease.routeId !== request.routeId) {
      throw new CredentialAccessDeniedV1("ROUTE_MISMATCH");
    }
    if (this.#clock().getTime() >= Date.parse(stored.lease.expiresAt)) {
      throw new CredentialAccessDeniedV1("LEASE_EXPIRED");
    }
    return stored.lease;
  }

  /**
   * The only credential-consuming boundary in the disposable vault. It sends one
   * exact JSON request to an origin pinned when the credential was registered and
   * never returns credential material or credential-bearing request headers.
   */
  public async sendMcpJsonWithLease(
    bindingInput: AuthenticatedSessionIdentityBindingV1,
    request: {
      readonly leaseId: string;
      readonly credentialProfileId: string;
      readonly audienceId: string;
      readonly routeId: string;
      readonly endpoint: string;
      readonly body: Uint8Array;
      readonly maxResponseBytes: number;
      readonly signal?: AbortSignal;
    }
  ): Promise<CredentialedMcpHttpResponseV1> {
    const binding = authenticatedSessionIdentityBindingV1Schema.parse(bindingInput);
    const lease = this.validateLease(binding, request);
    const storedProfile = this.#profiles.get(lease.credentialProfileId);
    if (storedProfile === undefined ||
      storedProfile.metadata.credentialProfileId !== request.credentialProfileId ||
      storedProfile.metadata.status !== "ACTIVE") {
      throw new CredentialAccessDeniedV1("PROFILE_UNAVAILABLE");
    }
    const endpoint = new URL(request.endpoint);
    if (!storedProfile.metadata.allowedEndpointOrigins.includes(endpoint.origin)) {
      throw new CredentialAccessDeniedV1("AUDIENCE_MISMATCH");
    }
    if (!Number.isSafeInteger(request.maxResponseBytes) || request.maxResponseBytes <= 0 ||
      request.maxResponseBytes > 64 * 1_024 * 1_024) {
      throw new RangeError("Response byte limit is invalid");
    }
    if (request.body.byteLength > 64 * 1_024 * 1_024) {
      throw new RangeError("Request body exceeds the disposable transport limit");
    }
    if (storedProfile.metadata.credentialKind === "CLIENT_CERTIFICATE") {
      throw new CredentialAccessDeniedV1("PROFILE_UNAVAILABLE");
    }

    const credential = storedProfile.material.toString("utf8");
    const credentialHeader = storedProfile.metadata.credentialKind === "BEARER_TOKEN"
      ? { Authorization: `Bearer ${credential}` }
      : { "X-MCP-API-Key": credential };
    const response = await fetch(endpoint, {
      method: "POST",
      redirect: "manual",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...credentialHeader
      },
      body: Buffer.from(request.body),
      ...(request.signal === undefined ? {} : { signal: request.signal })
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new Error("Downstream redirects are not permitted");
    }

    const chunks: Uint8Array[] = [];
    let byteLength = 0;
    if (response.body !== null) {
      for await (const chunk of response.body) {
        byteLength += chunk.byteLength;
        if (byteLength > request.maxResponseBytes) {
          throw new RangeError("Downstream response exceeds the result limit");
        }
        chunks.push(chunk);
      }
    }
    return Object.freeze({
      status: response.status,
      contentType: response.headers.get("content-type"),
      downstreamAuthentication: response.headers.get("mcp-server-authorization") ?? undefined,
      body: Buffer.concat(chunks, byteLength)
    });
  }

  public invalidateSession(transportSessionId: string): void {
    for (const stored of this.#leases.values()) {
      if (stored.lease.transportSessionId === transportSessionId) {
        stored.revoked = true;
      }
    }
  }

  public destroy(): void {
    for (const profile of this.#profiles.values()) {
      profile.material.fill(0);
    }
    this.#profiles.clear();
    this.#leases.clear();
  }
}
