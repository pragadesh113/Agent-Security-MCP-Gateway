import { randomUUID } from "node:crypto";

import { z } from "zod";

import type { AuthenticatedSessionIdentityBindingV1 } from "../identity/client-authentication-v1.js";
import { authenticatedSessionIdentityBindingV1Schema } from "../identity/client-authentication-v1.js";
import type { ClientApprovedCallExecutorV1 } from "./client-tool-call-v1.js";

const identifierSchema = z.string().min(1).max(128);

export interface ApprovalWebRuntimeSessionResolverV1 {
  resolve(input: {
    readonly approvalId: string;
    readonly humanId: string;
  }): Promise<AuthenticatedSessionIdentityBindingV1>;
}

export interface ApprovalWebRuntimeDispatchCoordinatorV1 {
  claimApprovalDispatch(input: {
    readonly approvalId: string;
    readonly humanId: string;
    readonly claimId: string;
    readonly claimedAt: string;
  }): Promise<void>;
  completeApprovalDispatch(input: {
    readonly approvalId: string;
    readonly claimId: string;
    readonly completedAt: string;
  }): Promise<void>;
  failApprovalDispatch(input: {
    readonly approvalId: string;
    readonly humanId: string;
    readonly claimId: string;
    readonly failedAt: string;
  }): Promise<void>;
}

/**
 * Trusted bridge used by the approval web boundary. The browser contributes no
 * agent session or forwarding authority; both are resolved by the protected
 * runtime before ClientApprovedCallExecutorV1 performs its durable checks.
 */
export class ApprovalWebRuntimeBridgeV1 {
  readonly #executor: ClientApprovedCallExecutorV1;
  readonly #sessions: ApprovalWebRuntimeSessionResolverV1;
  readonly #dispatches: ApprovalWebRuntimeDispatchCoordinatorV1;
  readonly #clock: () => Date;
  readonly #claimIdFactory: () => string;

  public constructor(input: {
    readonly executor: ClientApprovedCallExecutorV1;
    readonly sessions: ApprovalWebRuntimeSessionResolverV1;
    readonly dispatches: ApprovalWebRuntimeDispatchCoordinatorV1;
    readonly clock?: () => Date;
    readonly claimIdFactory?: () => string;
  }) {
    this.#executor = input.executor;
    this.#sessions = input.sessions;
    this.#dispatches = input.dispatches;
    this.#clock = input.clock ?? (() => new Date());
    this.#claimIdFactory = input.claimIdFactory ?? randomUUID;
  }

  public async executeApprovedCall(input: {
    readonly approvalId: string;
    readonly humanId: string;
  }): Promise<void> {
    const approvalId = identifierSchema.parse(input.approvalId);
    const humanId = identifierSchema.parse(input.humanId);
    const claimId = identifierSchema.parse(this.#claimIdFactory());
    const claimedAt = this.#clock().toISOString();
    await this.#dispatches.claimApprovalDispatch({ approvalId, humanId, claimId, claimedAt });
    try {
      const session = authenticatedSessionIdentityBindingV1Schema.parse(
        await this.#sessions.resolve({ approvalId, humanId })
      );
      await this.#executor.execute({ approvalId, session });
      await this.#dispatches.completeApprovalDispatch({
        approvalId,
        claimId,
        completedAt: this.#clock().toISOString()
      });
    } catch (error) {
      await this.#dispatches.failApprovalDispatch({
        approvalId,
        humanId,
        claimId,
        failedAt: this.#clock().toISOString()
      });
      throw error;
    }
  }
}
