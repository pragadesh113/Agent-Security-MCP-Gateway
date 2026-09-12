import { z } from "zod";

import { boundedProtocolJsonV1Schema } from "../contracts/boundary-v1.js";
import { identifierV1Schema } from "../contracts/v1.js";
import {
  authenticatedClientPrincipalV1Schema,
  authenticatedSessionIdentityBindingV1Schema,
  principalHasSameSubjectV1,
  principalMatchesSessionBindingV1,
  type AuthenticatedClientPrincipalV1,
  type AuthenticatedSessionIdentityBindingV1
} from "./client-authentication-v1.js";

export const sessionCompartmentV1Schema = z.enum([
  "ROUTES",
  "DOWNSTREAM_STATE",
  "APPROVALS",
  "QUOTAS",
  "RESULTS",
  "AUDIT"
]);

export type SessionCompartmentV1 = z.infer<typeof sessionCompartmentV1Schema>;

export interface SessionInvalidationSinkV1 {
  invalidateSession(transportSessionId: string): void;
}

export class SessionAccessDeniedV1 extends Error {
  public constructor() {
    super("Session access denied");
    this.name = "SessionAccessDeniedV1";
  }
}

interface StoredSessionV1 {
  readonly binding: AuthenticatedSessionIdentityBindingV1;
  status: "ACTIVE" | "QUARANTINED" | "CLOSED";
  trustState: "SHADOW_ACTIVE" | "FROZEN";
  reasonCodes: string[];
  readonly compartments: Record<SessionCompartmentV1, Map<string, unknown>>;
}

export interface SessionAdministrativeSnapshotV1 {
  readonly transportSessionId: string;
  readonly stateNamespace: string;
  readonly status: "ACTIVE" | "QUARANTINED" | "CLOSED";
  readonly trustState: "SHADOW_ACTIVE" | "FROZEN";
  readonly reasonCodes: readonly string[];
  readonly compartmentEntryCounts: Readonly<Record<SessionCompartmentV1, number>>;
}

function createCompartments(): StoredSessionV1["compartments"] {
  return {
    ROUTES: new Map(),
    DOWNSTREAM_STATE: new Map(),
    APPROVALS: new Map(),
    QUOTAS: new Map(),
    RESULTS: new Map(),
    AUDIT: new Map()
  };
}

/** Disposable, process-local state used until the durable session store is delivered. */
export class DisposableSessionStateRepositoryV1 {
  readonly #sessions = new Map<string, StoredSessionV1>();
  readonly #invalidationSinks: readonly SessionInvalidationSinkV1[];

  public constructor(invalidationSinks: readonly SessionInvalidationSinkV1[] = []) {
    this.#invalidationSinks = invalidationSinks;
  }

  public createSession(bindingInput: AuthenticatedSessionIdentityBindingV1): void {
    const binding = authenticatedSessionIdentityBindingV1Schema.parse(bindingInput);
    if (this.#sessions.has(binding.transportSessionId)) {
      throw new Error("Session already exists");
    }
    this.#sessions.set(binding.transportSessionId, {
      binding,
      status: "ACTIVE",
      trustState: "SHADOW_ACTIVE",
      reasonCodes: [],
      compartments: createCompartments()
    });
  }

  public authorizeSession(
    principalInput: AuthenticatedClientPrincipalV1,
    transportSessionId: string
  ): AuthenticatedSessionIdentityBindingV1 {
    const principal = authenticatedClientPrincipalV1Schema.parse(principalInput);
    const session = this.#sessions.get(transportSessionId);
    if (session === undefined || session.status !== "ACTIVE") {
      throw new SessionAccessDeniedV1();
    }
    if (principalMatchesSessionBindingV1(principal, session.binding)) {
      return session.binding;
    }
    if (principalHasSameSubjectV1(principal, session.binding)) {
      this.#quarantine(session);
    }
    throw new SessionAccessDeniedV1();
  }

  public put(
    principal: AuthenticatedClientPrincipalV1,
    transportSessionId: string,
    compartmentInput: SessionCompartmentV1,
    keyInput: string,
    valueInput: unknown
  ): void {
    const session = this.#authorizedSession(principal, transportSessionId);
    const compartment = sessionCompartmentV1Schema.parse(compartmentInput);
    const key = identifierV1Schema.parse(keyInput);
    const value = boundedProtocolJsonV1Schema.parse(valueInput);
    session.compartments[compartment].set(key, structuredClone(value));
  }

  public get(
    principal: AuthenticatedClientPrincipalV1,
    transportSessionId: string,
    compartmentInput: SessionCompartmentV1,
    keyInput: string
  ): unknown {
    const session = this.#authorizedSession(principal, transportSessionId);
    const compartment = sessionCompartmentV1Schema.parse(compartmentInput);
    const key = identifierV1Schema.parse(keyInput);
    const value = session.compartments[compartment].get(key);
    return value === undefined ? undefined : structuredClone(value);
  }

  public closeSession(
    principal: AuthenticatedClientPrincipalV1,
    transportSessionId: string
  ): void {
    const session = this.#authorizedSession(principal, transportSessionId);
    session.status = "CLOSED";
    session.trustState = "FROZEN";
    session.reasonCodes = ["session.closed"];
    this.#clearActiveState(session);
    this.#invalidate(transportSessionId);
  }

  public inspectSession(transportSessionId: string): SessionAdministrativeSnapshotV1 | undefined {
    const session = this.#sessions.get(transportSessionId);
    if (session === undefined) {
      return undefined;
    }
    return Object.freeze({
      transportSessionId,
      stateNamespace: session.binding.stateNamespace,
      status: session.status,
      trustState: session.trustState,
      reasonCodes: Object.freeze([...session.reasonCodes]),
      compartmentEntryCounts: Object.freeze({
        ROUTES: session.compartments.ROUTES.size,
        DOWNSTREAM_STATE: session.compartments.DOWNSTREAM_STATE.size,
        APPROVALS: session.compartments.APPROVALS.size,
        QUOTAS: session.compartments.QUOTAS.size,
        RESULTS: session.compartments.RESULTS.size,
        AUDIT: session.compartments.AUDIT.size
      })
    });
  }

  #authorizedSession(
    principal: AuthenticatedClientPrincipalV1,
    transportSessionId: string
  ): StoredSessionV1 {
    this.authorizeSession(principal, transportSessionId);
    const session = this.#sessions.get(transportSessionId);
    if (session === undefined) {
      throw new SessionAccessDeniedV1();
    }
    return session;
  }

  #quarantine(session: StoredSessionV1): void {
    session.status = "QUARANTINED";
    session.trustState = "FROZEN";
    session.reasonCodes = ["identity.credential_rotated"];
    this.#clearActiveState(session);
    this.#invalidate(session.binding.transportSessionId);
  }

  #clearActiveState(session: StoredSessionV1): void {
    for (const compartment of [
      "ROUTES",
      "DOWNSTREAM_STATE",
      "APPROVALS",
      "QUOTAS"
    ] as const) {
      session.compartments[compartment].clear();
    }
  }

  #invalidate(transportSessionId: string): void {
    for (const sink of this.#invalidationSinks) {
      sink.invalidateSession(transportSessionId);
    }
  }
}
