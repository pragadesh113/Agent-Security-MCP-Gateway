import { z } from "zod";

import { identifierV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";
import {
  authenticatedClientPrincipalV1Schema,
  type AuthenticatedClientPrincipalV1,
  type ClientAuthenticationAttemptV1
} from "./client-authentication-v1.js";

export const TLS_CLIENT_AUTH_EKU_OID_V1 = "1.3.6.1.5.5.7.3.2";

const sha256FingerprintV1Schema = z.string().regex(/^[a-f0-9]{64}$/u);

export const trustedTlsPeerFactsV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    authorized: z.boolean(),
    authorizationError: z.string().trim().min(1).max(256).nullable(),
    protocol: z.enum(["TLSv1.2", "TLSv1.3"]),
    certificate: z
      .object({
        fingerprintSha256: sha256FingerprintV1Schema,
        validFrom: utcTimestampV1Schema,
        validTo: utcTimestampV1Schema,
        extendedKeyUsageOids: z
          .array(z.string().regex(/^\d+(?:\.\d+)+$/u))
          .min(1)
          .max(32)
          .refine((values) => new Set(values).size === values.length, {
            message: "Extended key usage OIDs must be unique"
          })
      })
      .strict()
  })
  .strict()
  .superRefine((facts, context) => {
    if (facts.authorized && facts.authorizationError !== null) {
      context.addIssue({
        code: "custom",
        path: ["authorizationError"],
        message: "An authorized TLS peer cannot have an authorization error"
      });
    }
    if (new Date(facts.certificate.validTo) <= new Date(facts.certificate.validFrom)) {
      context.addIssue({
        code: "custom",
        path: ["certificate", "validTo"],
        message: "TLS certificate validity must end after it begins"
      });
    }
  });

export const protectedClientCredentialRecordV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    fingerprintSha256: sha256FingerprintV1Schema,
    credentialId: identifierV1Schema,
    identityRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    status: z.enum(["ACTIVE", "REVOKED"]),
    userId: identifierV1Schema,
    agentId: identifierV1Schema,
    clientId: identifierV1Schema,
    host: z
      .object({
        hostId: identifierV1Schema,
        name: z.string().trim().min(1).max(128),
        version: z.string().trim().min(1).max(64)
      })
      .strict(),
    validFrom: utcTimestampV1Schema,
    validTo: utcTimestampV1Schema,
    activatedAt: utcTimestampV1Schema,
    revokedAt: utcTimestampV1Schema.nullable()
  })
  .strict()
  .superRefine((record, context) => {
    const validFrom = new Date(record.validFrom);
    const validTo = new Date(record.validTo);
    const activatedAt = new Date(record.activatedAt);
    if (validTo <= validFrom) {
      context.addIssue({
        code: "custom",
        path: ["validTo"],
        message: "Credential validity must end after it begins"
      });
    }
    if (activatedAt < validFrom || activatedAt >= validTo) {
      context.addIssue({
        code: "custom",
        path: ["activatedAt"],
        message: "Credential activation must fall inside its validity window"
      });
    }
    if (record.status === "ACTIVE" && record.revokedAt !== null) {
      context.addIssue({
        code: "custom",
        path: ["revokedAt"],
        message: "An active credential cannot have a revocation time"
      });
    }
    if (record.status === "REVOKED" && record.revokedAt === null) {
      context.addIssue({
        code: "custom",
        path: ["revokedAt"],
        message: "A revoked credential requires a revocation time"
      });
    }
  });

export type TrustedTlsPeerFactsV1 = z.infer<typeof trustedTlsPeerFactsV1Schema>;
export type ProtectedClientCredentialRecordV1 = z.infer<
  typeof protectedClientCredentialRecordV1Schema
>;

export interface ProtectedClientCredentialStoreV1 {
  resolveActiveCredential(
    fingerprintSha256: string,
    now: Date
  ): Promise<ProtectedClientCredentialRecordV1 | null>;
}

export interface ProtectedClientIdentityProviderV1Options {
  readonly credentialStore: ProtectedClientCredentialStoreV1;
  readonly clock?: () => Date;
}

export class ProtectedClientIdentityUnavailableV1 extends Error {
  public constructor() {
    super("Protected client identity is unavailable");
    this.name = "ProtectedClientIdentityUnavailableV1";
  }
}

export function normalizeTlsCertificateFingerprintSha256V1(input: string): string {
  const normalized = input.trim().replaceAll(":", "").toLowerCase();
  return sha256FingerprintV1Schema.parse(normalized);
}

function dateContains(date: Date, validFrom: string, validTo: string): boolean {
  const milliseconds = date.getTime();
  return milliseconds >= new Date(validFrom).getTime() &&
    milliseconds < new Date(validTo).getTime();
}

export class ProtectedClientIdentityProviderV1 {
  readonly #credentialStore: ProtectedClientCredentialStoreV1;
  readonly #clock: () => Date;

  public constructor(options: ProtectedClientIdentityProviderV1Options) {
    this.#credentialStore = options.credentialStore;
    this.#clock = options.clock ?? (() => new Date());
  }

  public async authenticate(
    attemptInput: ClientAuthenticationAttemptV1
  ): Promise<AuthenticatedClientPrincipalV1 | undefined> {
    const tlsPeer = trustedTlsPeerFactsV1Schema.safeParse(attemptInput.trustedTlsPeer);
    if (!tlsPeer.success) {
      throw new ProtectedClientIdentityUnavailableV1();
    }
    if (!tlsPeer.data.authorized) {
      return undefined;
    }
    if (!tlsPeer.data.certificate.extendedKeyUsageOids.includes(
      TLS_CLIENT_AUTH_EKU_OID_V1
    )) {
      return undefined;
    }

    const now = this.#clock();
    if (!Number.isFinite(now.getTime())) {
      throw new ProtectedClientIdentityUnavailableV1();
    }
    const certificate = tlsPeer.data.certificate;
    if (!dateContains(now, certificate.validFrom, certificate.validTo)) {
      return undefined;
    }

    let stored: ProtectedClientCredentialRecordV1 | null;
    try {
      stored = await this.#credentialStore.resolveActiveCredential(
        certificate.fingerprintSha256,
        now
      );
    } catch {
      throw new ProtectedClientIdentityUnavailableV1();
    }
    if (stored === null) {
      return undefined;
    }
    const record = protectedClientCredentialRecordV1Schema.safeParse(stored);
    if (!record.success) {
      throw new ProtectedClientIdentityUnavailableV1();
    }
    if (record.data.fingerprintSha256 !== certificate.fingerprintSha256) {
      throw new ProtectedClientIdentityUnavailableV1();
    }
    if (record.data.status !== "ACTIVE" ||
      !dateContains(now, record.data.validFrom, record.data.validTo) ||
      new Date(record.data.activatedAt).getTime() > now.getTime()) {
      return undefined;
    }

    return authenticatedClientPrincipalV1Schema.parse({
      schemaVersion: "1.0.0",
      userId: record.data.userId,
      agentId: record.data.agentId,
      clientId: record.data.clientId,
      host: record.data.host,
      authentication: {
        method: "MUTUAL_TLS",
        credentialId: record.data.credentialId,
        identityRevision: record.data.identityRevision,
        authenticatedAt: now.toISOString()
      }
    });
  }
}
