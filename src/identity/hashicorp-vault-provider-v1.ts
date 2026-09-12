import { z } from "zod";

import {
  approvedSecretManagerDescriptorV1Schema,
  type ApprovedSecretManagerDescriptorV1,
  type ApprovedSecretManagerProviderV1,
  type SecretManagerExactRevisionV1
} from "./protected-credential-broker-v1.js";

const MAX_VAULT_RESPONSE_BYTES = 64 * 1_024;
const vaultReferenceV1Schema = z.string().trim().regex(
  /^kv-v2:\/\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9._~/-]+#[a-zA-Z0-9._-]+$/u
);
const vaultKvV2ResponseV1Schema = z.looseObject({
  data: z.object({
    data: z.record(z.string(), z.unknown()),
    metadata: z.looseObject({ version: z.number().int().positive() })
  }).strict()
});

export interface HashiCorpVaultKvV2ProviderV1Options {
  readonly descriptor: ApprovedSecretManagerDescriptorV1;
  readonly endpointOrigin: string;
  readonly tokenProvider: (signal?: AbortSignal) => Promise<Uint8Array>;
  readonly fetchImplementation?: typeof fetch;
  readonly allowInsecureLoopbackForDisposableTests?: boolean;
}

function canonicalVaultOrigin(value: string, allowInsecureLoopback: boolean): string {
  const url = new URL(value);
  if (url.origin !== value || url.username !== "" || url.password !== "" ||
    (url.protocol !== "https:" && !(allowInsecureLoopback && url.protocol === "http:" &&
      (url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "::1")))) {
    throw new Error("Vault endpoint must be a canonical HTTPS origin");
  }
  return url.origin;
}

function parseReference(reference: string): { mount: string; path: string; field: string } {
  const parsed = vaultReferenceV1Schema.parse(reference);
  const match = /^kv-v2:\/\/([^/]+)\/(.+)#([^#]+)$/u.exec(parsed);
  if (match === null) throw new Error("Vault KV v2 reference is invalid");
  const [, mount, path, field] = match;
  if (mount === undefined || path === undefined || field === undefined ||
    path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error("Vault KV v2 reference is invalid");
  }
  return { mount, path, field };
}

export class HashiCorpVaultKvV2ProviderV1 implements ApprovedSecretManagerProviderV1 {
  public readonly descriptor: ApprovedSecretManagerDescriptorV1;
  readonly #origin: string;
  readonly #tokenProvider: (signal?: AbortSignal) => Promise<Uint8Array>;
  readonly #fetch: typeof fetch;

  public constructor(options: HashiCorpVaultKvV2ProviderV1Options) {
    this.descriptor = approvedSecretManagerDescriptorV1Schema.parse(options.descriptor);
    if (this.descriptor.providerType !== "HASHICORP_VAULT") {
      throw new Error("HashiCorp Vault provider requires a HASHICORP_VAULT descriptor");
    }
    this.#origin = canonicalVaultOrigin(
      options.endpointOrigin,
      options.allowInsecureLoopbackForDisposableTests === true
    );
    this.#tokenProvider = options.tokenProvider;
    this.#fetch = options.fetchImplementation ?? fetch;
  }

  public async fetchExactRevision(input: {
    readonly secretReference: string;
    readonly credentialProfileId: string;
    readonly credentialRevision: number;
    readonly signal?: AbortSignal;
  }): Promise<SecretManagerExactRevisionV1 | null> {
    if (!Number.isSafeInteger(input.credentialRevision) || input.credentialRevision <= 0) {
      throw new Error("Vault credential revision must be a positive safe integer");
    }
    const reference = parseReference(input.secretReference);
    const encodedPath = reference.path.split("/").map(encodeURIComponent).join("/");
    let token: Uint8Array | undefined;
    let tokenCopy: Buffer | undefined;
    try {
      token = await this.#tokenProvider(input.signal);
      if (!(token instanceof Uint8Array) || token.byteLength < 8 || token.byteLength > 4_096) {
        throw new Error("Vault authentication material is unavailable");
      }
      tokenCopy = Buffer.from(token);
      const response = await this.#fetch(
        `${this.#origin}/v1/${encodeURIComponent(reference.mount)}/data/${encodedPath}?version=${String(input.credentialRevision)}`,
        {
          method: "GET",
          redirect: "manual",
          headers: { Accept: "application/json", "X-Vault-Token": tokenCopy.toString("utf8") },
          ...(input.signal === undefined ? {} : { signal: input.signal })
        }
      );
      if (response.status === 404) {
        await response.body?.cancel();
        return null;
      }
      if (!response.ok || (response.status >= 300 && response.status < 400)) {
        await response.body?.cancel();
        throw new Error("Vault exact-revision retrieval failed");
      }
      const body = await response.arrayBuffer();
      if (body.byteLength > MAX_VAULT_RESPONSE_BYTES) {
        throw new Error("Vault response exceeds the allowed size");
      }
      const payload = vaultKvV2ResponseV1Schema.parse(JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(body)
      ));
      if (payload.data.metadata.version !== input.credentialRevision) {
        throw new Error("Vault returned a substituted secret revision");
      }
      const value = payload.data.data[reference.field];
      if (typeof value !== "string") return null;
      return {
        providerId: this.descriptor.providerId,
        secretReference: input.secretReference,
        credentialProfileId: input.credentialProfileId,
        credentialRevision: input.credentialRevision,
        material: Buffer.from(value, "utf8")
      };
    } finally {
      tokenCopy?.fill(0);
      token?.fill(0);
    }
  }
}

export { vaultReferenceV1Schema };
