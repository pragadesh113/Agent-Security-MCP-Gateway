export type JsonRpcId = number | string;

export type JsonValue =
  | boolean
  | null
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id: JsonRpcId;
  readonly method: string;
  readonly params?: JsonValue;
}

export interface JsonRpcNotification {
  readonly jsonrpc: "2.0";
  readonly method: string;
  readonly params?: JsonValue;
}

export interface DisposableMcpInitializeParams {
  readonly protocolVersion: string;
  readonly capabilities: { readonly [key: string]: JsonValue };
  readonly clientInfo: {
    readonly name: string;
    readonly version: string;
  };
}

export type ResponseBodyError =
  | "EMPTY_BODY"
  | "INVALID_JSON"
  | "RESPONSE_TOO_LARGE";

export interface DisposableMcpHttpResponse {
  readonly status: number;
  readonly ok: boolean;
  readonly headers: Readonly<Record<string, string>>;
  readonly text: string;
  readonly json: unknown;
  readonly bodyError: ResponseBodyError | undefined;
}

export interface DisposableMcpHttpClientOptions {
  readonly authorizationHeader: string;
  readonly maxResponseBytes?: number;
}

const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_CONFIGURED_RESPONSE_BYTES = 16 * 1024 * 1024;
const SESSION_HEADER = "Mcp-Session-Id";
const PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version";

function parseLoopbackEndpoint(endpoint: string | URL): URL {
  const parsed = new URL(endpoint.toString());
  const allowedHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);

  if (
    parsed.protocol !== "http:" ||
    !allowedHosts.has(parsed.hostname.toLowerCase()) ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    throw new TypeError(
      "Disposable MCP endpoints must use credential-free HTTP on 127.0.0.1, localhost, or [::1].",
    );
  }

  return parsed;
}

function validateResponseLimit(value: number | undefined): number {
  const limit = value ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > MAX_CONFIGURED_RESPONSE_BYTES
  ) {
    throw new RangeError(
      `maxResponseBytes must be an integer from 1 through ${String(MAX_CONFIGURED_RESPONSE_BYTES)}.`,
    );
  }
  return limit;
}

function snapshotHeaders(headers: Headers): Readonly<Record<string, string>> {
  return Object.freeze(Object.fromEntries(headers.entries()));
}

async function readBoundedBody(
  response: Response,
  maxResponseBytes: number,
): Promise<Pick<DisposableMcpHttpResponse, "bodyError" | "json" | "text">> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (Number.isFinite(length) && length > maxResponseBytes) {
      await response.body?.cancel();
      return { bodyError: "RESPONSE_TOO_LARGE", json: undefined, text: "" };
    }
  }

  if (response.body === null) {
    return { bodyError: "EMPTY_BODY", json: undefined, text: "" };
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;

  for (;;) {
    const item = await reader.read();
    if (item.done) {
      break;
    }

    if (byteLength + item.value.byteLength > maxResponseBytes) {
      await reader.cancel();
      return { bodyError: "RESPONSE_TOO_LARGE", json: undefined, text: "" };
    }

    chunks.push(item.value);
    byteLength += item.value.byteLength;
  }

  if (byteLength === 0) {
    return { bodyError: "EMPTY_BODY", json: undefined, text: "" };
  }

  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  const text = new TextDecoder().decode(bytes);
  try {
    return { bodyError: undefined, json: JSON.parse(text) as unknown, text };
  } catch {
    return { bodyError: "INVALID_JSON", json: undefined, text };
  }
}

function negotiatedVersionFrom(json: unknown): string | undefined {
  if (typeof json !== "object" || json === null || !("result" in json)) {
    return undefined;
  }
  const result = json.result;
  if (typeof result !== "object" || result === null || !("protocolVersion" in result)) {
    return undefined;
  }
  const protocolVersion = result.protocolVersion;
  return typeof protocolVersion === "string" && protocolVersion.length <= 64
    ? protocolVersion
    : undefined;
}

/**
 * Minimal test client for a disposable MCP Streamable HTTP endpoint.
 *
 * Redirects are rejected so a loopback fixture cannot be redirected to an external
 * address. The client stores only the opaque session identifier and protocol version
 * returned by a successful initialize response.
 */
export class DisposableMcpHttpClientV1 {
  public readonly endpoint: URL;
  public sessionId: string | undefined;
  public negotiatedProtocolVersion: string | undefined;

  readonly #maxResponseBytes: number;
  readonly #authorizationHeader: string;
  #nextRequestId = 1;

  public constructor(
    endpoint: string | URL,
    options: DisposableMcpHttpClientOptions,
  ) {
    this.endpoint = parseLoopbackEndpoint(endpoint);
    if (
      options.authorizationHeader.trim().length === 0 ||
      options.authorizationHeader.length > 2_048
    ) {
      throw new RangeError("authorizationHeader must contain 1 through 2048 characters.");
    }
    this.#authorizationHeader = options.authorizationHeader;
    this.#maxResponseBytes = validateResponseLimit(options.maxResponseBytes);
  }

  public async initialize(
    params: DisposableMcpInitializeParams,
    id: JsonRpcId = this.#takeRequestId(),
  ): Promise<DisposableMcpHttpResponse> {
    const response = await this.#exchange("POST", {
      jsonrpc: "2.0",
      id,
      method: "initialize",
      params: params as unknown as JsonValue,
    });

    const sessionId = response.headers[SESSION_HEADER.toLowerCase()];
    const protocolVersion = negotiatedVersionFrom(response.json);
    if (
      response.ok &&
      sessionId !== undefined &&
      sessionId.length > 0 &&
      sessionId.length <= 256 &&
      protocolVersion !== undefined
    ) {
      this.sessionId = sessionId;
      this.negotiatedProtocolVersion = protocolVersion;
    }

    return response;
  }

  public async sendInitialized(): Promise<DisposableMcpHttpResponse> {
    return this.sendNotification("notifications/initialized");
  }

  public async sendNotification(
    method: string,
    params?: JsonValue,
  ): Promise<DisposableMcpHttpResponse> {
    const notification: JsonRpcNotification =
      params === undefined
        ? { jsonrpc: "2.0", method }
        : { jsonrpc: "2.0", method, params };
    return this.#exchange("POST", notification, this.#sessionHeaders());
  }

  public async ping(
    id: JsonRpcId = this.#takeRequestId(),
  ): Promise<DisposableMcpHttpResponse> {
    return this.sendRequest("ping", undefined, id);
  }

  public async sendRequest(
    method: string,
    params?: JsonValue,
    id: JsonRpcId = this.#takeRequestId(),
  ): Promise<DisposableMcpHttpResponse> {
    const request: JsonRpcRequest =
      params === undefined
        ? { jsonrpc: "2.0", id, method }
        : { jsonrpc: "2.0", id, method, params };
    return this.#exchange("POST", request, this.#sessionHeaders());
  }

  public async terminate(): Promise<DisposableMcpHttpResponse> {
    return this.#exchange("DELETE", undefined, this.#sessionHeaders());
  }

  #takeRequestId(): number {
    const id = this.#nextRequestId;
    this.#nextRequestId += 1;
    return id;
  }

  #sessionHeaders(): Record<string, string> {
    if (
      this.sessionId === undefined ||
      this.negotiatedProtocolVersion === undefined
    ) {
      throw new Error("A successful initialize response is required first.");
    }
    return {
      [SESSION_HEADER]: this.sessionId,
      [PROTOCOL_VERSION_HEADER]: this.negotiatedProtocolVersion,
    };
  }

  async #exchange(
    method: "DELETE" | "POST",
    payload?: JsonRpcRequest | JsonRpcNotification,
    lifecycleHeaders: Readonly<Record<string, string>> = {},
  ): Promise<DisposableMcpHttpResponse> {
    const headers: Record<string, string> = {
      Accept: "application/json, text/event-stream",
      Authorization: this.#authorizationHeader,
      ...lifecycleHeaders,
    };
    if (payload !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    const init: RequestInit = {
      headers,
      method,
      redirect: "error",
    };
    if (payload !== undefined) {
      init.body = JSON.stringify(payload);
    }

    const rawResponse = await fetch(this.endpoint, init);
    const body = await readBoundedBody(rawResponse, this.#maxResponseBytes);
    return Object.freeze({
      status: rawResponse.status,
      ok: rawResponse.ok,
      headers: snapshotHeaders(rawResponse.headers),
      ...body,
    });
  }
}
