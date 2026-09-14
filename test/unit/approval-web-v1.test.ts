import { createServer, type Server } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  ApprovalWebStaleDecisionV1,
  approvalWebRecordV1Schema,
  createApprovalWebAppV1,
  type ApprovalWebHumanPrincipalV1,
  type ApprovalWebRecordV1,
  type ApprovalWebSessionV1,
  type ApprovalWebStoreV1
} from "../../src/interfaces/approval-web-v1.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

const now = new Date("2026-09-12T12:00:00.000Z");
const origin = "https://approval.example.test";
const sessionToken = "s".repeat(43);
const csrfToken = "c".repeat(43);

const principal: ApprovalWebHumanPrincipalV1 = {
  schemaVersion: "1.0.0",
  humanId: "human-web",
  authenticationMethod: "MUTUAL_TLS",
  credentialId: "human-cert-web",
  identityRevision: 1,
  authenticatedAt: now.toISOString()
};

function record(): ApprovalWebRecordV1 {
  const fixture = createPostgresTrajectoryFixtureV1("web", now);
  const approval = {
    ...fixture.approval,
    state: "PENDING" as const,
    decidedAt: null,
    decidedByHumanId: null
  };
  return approvalWebRecordV1Schema.parse({
    schemaVersion: "1.0.0",
    revision: 1,
    approval,
    view: {
      schemaVersion: "1.0.0",
      interfaceId: "interface-web",
      requestId: fixture.action.requestId,
      actionId: fixture.action.actionId,
      decisionId: fixture.decision.decisionId,
      requester: { ...fixture.action.identity, sessionId: fixture.action.sessionId },
      route: fixture.action.route,
      targets: fixture.action.resources,
      dataFlow: fixture.action.dataFlow,
      provenance: {
        parserId: fixture.action.parsingEvidence.parserId,
        parserVersion: fixture.action.parsingEvidence.parserVersion,
        parsingStatus: fixture.action.parsingEvidence.status,
        influences: fixture.action.influences
      },
      riskTier: fixture.decision.tier,
      actionEffect: fixture.action.effect,
      decision: "REQUIRE_APPROVAL",
      reversibility: fixture.action.reversibility,
      recoveryClass: fixture.action.reversibility,
      blastRadius: "LOCAL_SINGLE",
      relatedAttemptIds: [],
      coverage: "ENFORCED",
      coverageAssessmentId: "coverage-web",
      coverageEvidenceDigest: "a".repeat(64),
      missingGuarantees: [],
      possiblePartialEffects: false,
      generatedFromCanonicalData: true,
      generatedAt: now.toISOString()
    },
    outcome: null
  });
}

class MemoryStore implements ApprovalWebStoreV1 {
  public current = record();
  public decisions = 0;
  public session: ApprovalWebSessionV1 | null = null;

  public createSession(input: Parameters<ApprovalWebStoreV1["createSession"]>[0]): Promise<ApprovalWebSessionV1> {
    this.session = {
      schemaVersion: "1.0.0",
      sessionIdDigest: input.sessionIdDigest,
      csrfTokenDigest: input.csrfTokenDigest,
      humanId: input.principal.humanId,
      authenticationMethod: input.principal.authenticationMethod,
      credentialId: input.principal.credentialId,
      identityRevision: input.principal.identityRevision,
      policyScopeIds: [this.current.view.route.policyScopeId],
      createdAt: input.createdAt,
      expiresAt: input.expiresAt
    };
    return Promise.resolve(this.session);
  }

  public readAuthorizedSession(
    input: Parameters<ApprovalWebStoreV1["readAuthorizedSession"]>[0]
  ): Promise<ApprovalWebSessionV1 | null> {
    if (this.session?.sessionIdDigest !== input.sessionIdDigest ||
      this.session.humanId !== input.principal.humanId) return Promise.resolve(null);
    return Promise.resolve(this.session);
  }

  public listPending(): Promise<readonly ApprovalWebRecordV1[]> {
    return Promise.resolve(this.current.approval.state === "PENDING" ? [this.current] : []);
  }

  public readApproval(_session: ApprovalWebSessionV1, approvalId: string): Promise<ApprovalWebRecordV1 | null> {
    return Promise.resolve(approvalId === this.current.approval.approvalId ? this.current : null);
  }

  public decide(input: Parameters<ApprovalWebStoreV1["decide"]>[0]): Promise<ApprovalWebRecordV1> {
    if (input.expectedRevision !== this.current.revision || this.current.approval.state !== "PENDING") {
      throw new ApprovalWebStaleDecisionV1();
    }
    this.decisions += 1;
    this.current = approvalWebRecordV1Schema.parse({
      ...this.current,
      revision: this.current.revision + 1,
      approval: {
        ...this.current.approval,
        state: input.decision === "APPROVE" ? "APPROVED" : "DENIED",
        decidedAt: input.decidedAt,
        decidedByHumanId: input.session.humanId
      }
    });
    return Promise.resolve(this.current);
  }
}

const servers = new Set<Server>();

afterEach(async () => {
  await Promise.all([...servers].map(async (server) => new Promise<void>((resolve) => server.close(() => {
    resolve();
  }))));
  servers.clear();
});

async function start(store = new MemoryStore(), authenticated = true) {
  const tokens = [sessionToken, csrfToken];
  const app = createApprovalWebAppV1({
    origin,
    authenticateHuman: () => authenticated ? principal : null,
    store,
    clock: () => new Date(now.getTime() + 10_000),
    tokenFactory: () => tokens.shift() ?? "x".repeat(43),
    readStaticAsset: (path) => path === "/index.html"
      ? { contentType: "text/html; charset=utf-8", body: "<!doctype html><title>Approval</title>" }
      : null
  });
  const server = createServer(app);
  servers.add(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Test server did not bind");
  return { store, url: `http://127.0.0.1:${String(address.port)}` };
}

const fetchHeaders = { Origin: origin, "Sec-Fetch-Site": "same-origin" };

async function createSession(url: string, fixationCookie?: string) {
  const response = await fetch(`${url}/approval/api/session`, {
    method: "POST",
    headers: {
      ...fetchHeaders,
      ...(fixationCookie === undefined ? {} : { Cookie: fixationCookie })
    }
  });
  const cookie = response.headers.get("set-cookie");
  return { response, cookie: cookie?.split(";", 1)[0] ?? "" };
}

describe("authenticated approval web boundary", () => {
  it("serves only hardened no-store assets after independent human authentication", async () => {
    const { url } = await start();
    const response = await fetch(`${url}/approval/`);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Approval");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("x-frame-options")).toBe("DENY");

    const unauthenticated = await start(new MemoryStore(), false);
    expect((await fetch(`${unauthenticated.url}/approval/`)).status).toBe(401);
    expect((await fetch(`${url}/approval/assets/..%2Fsecret`)).status).toBe(404);
  });

  it("accepts browser-style same-origin reads without an Origin header and rejects a mismatched one", async () => {
    const { url } = await start();
    const created = await createSession(url);
    const read = await fetch(`${url}/approval/api/pending`, {
      headers: { "Sec-Fetch-Site": "same-origin", Cookie: created.cookie }
    });
    expect(read.status).toBe(200);
    const confused = await fetch(`${url}/approval/api/pending`, {
      headers: { Origin: "https://attacker.example", "Sec-Fetch-Site": "same-origin", Cookie: created.cookie }
    });
    expect(confused.status).toBe(403);
  });

  it("replaces a fixation cookie and returns live scope-filtered pending detail", async () => {
    const { url, store } = await start();
    const fixation = `__Host-agent_security_approval=${"f".repeat(43)}`;
    const session = await createSession(url, fixation);
    expect(session.response.status).toBe(201);
    expect(session.cookie).toBe(`__Host-agent_security_approval=${sessionToken}`);
    expect(session.response.headers.get("set-cookie")).toContain("Secure; HttpOnly; SameSite=Strict");
    const sessionBody = await session.response.json() as { csrfToken?: unknown; expiresAt?: unknown };
    expect(sessionBody.csrfToken).toBe(csrfToken);
    expect(typeof sessionBody.expiresAt).toBe("string");

    const pending = await fetch(`${url}/approval/api/pending`, {
      headers: { ...fetchHeaders, Cookie: session.cookie }
    });
    expect(pending.status).toBe(200);
    const pendingBody = await pending.json() as { approvals: Array<Record<string, unknown>> };
    expect(pendingBody.approvals).toEqual([expect.objectContaining({
      approvalId: store.current.approval.approvalId,
      policyScopeId: store.current.view.route.policyScopeId,
      state: "PENDING"
    })]);
    expect(JSON.stringify(pendingBody)).not.toContain("actionHash");

    const detail = await fetch(`${url}/approval/api/approvals/${store.current.approval.approvalId}`, {
      headers: { ...fetchHeaders, Cookie: session.cookie }
    });
    expect(detail.status).toBe(200);
    expect(detail.headers.get("etag")).toBe('"1"');
    expect(await detail.json()).toMatchObject({ approval: { state: "PENDING" }, view: { generatedFromCanonicalData: true } });
  });

  it("rejects cross-origin, missing CSRF, stale, and client-supplied authority", async () => {
    const { url, store } = await start();
    const session = await createSession(url);
    const endpoint = `${url}/approval/api/approvals/${store.current.approval.approvalId}/decision`;
    const base = {
      method: "POST",
      headers: {
        ...fetchHeaders,
        Cookie: session.cookie,
        "Content-Type": "application/json",
        "If-Match": '"1"',
        "X-CSRF-Token": csrfToken
      },
      body: JSON.stringify({ schemaVersion: "1.0.0", decision: "APPROVE" })
    };
    expect((await fetch(endpoint, {
      ...base,
      headers: { ...base.headers, Origin: "https://approval.example.test.attacker.invalid" }
    })).status).toBe(403);
    expect((await fetch(endpoint, {
      ...base,
      headers: { ...base.headers, "X-CSRF-Token": "z".repeat(43) }
    })).status).toBe(403);
    expect((await fetch(endpoint, {
      ...base,
      body: JSON.stringify({ schemaVersion: "1.0.0", decision: "APPROVE", humanId: "attacker" })
    })).status).toBe(400);
    expect((await fetch(endpoint, {
      ...base,
      headers: { ...base.headers, "If-Match": 'W/"1"' }
    })).status).toBe(403);
    expect(store.decisions).toBe(0);
  });

  it("allows one exact decision and makes duplicate and multi-tab races stale", async () => {
    const { url, store } = await start();
    const session = await createSession(url);
    const endpoint = `${url}/approval/api/approvals/${store.current.approval.approvalId}/decision`;
    const request = () => fetch(endpoint, {
      method: "POST",
      headers: {
        ...fetchHeaders,
        Cookie: session.cookie,
        "Content-Type": "application/json",
        "If-Match": '"1"',
        "X-CSRF-Token": csrfToken
      },
      body: JSON.stringify({ schemaVersion: "1.0.0", decision: "APPROVE" })
    });
    const responses = await Promise.all([request(), request()]);
    expect(responses.map((item) => item.status).sort()).toEqual([200, 409]);
    expect(store.decisions).toBe(1);
    expect(store.current.approval).toMatchObject({ state: "APPROVED", decidedByHumanId: principal.humanId });

    const reload = await fetch(`${url}/approval/api/approvals/${store.current.approval.approvalId}`, {
      headers: { ...fetchHeaders, Cookie: session.cookie }
    });
    expect(await reload.json()).toMatchObject({ revision: 2, approval: { state: "APPROVED" } });
  });
});
