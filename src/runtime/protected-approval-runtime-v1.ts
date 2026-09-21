import {
  downstreamServerRouteBindingV1Schema,
  type DownstreamServerRouteBindingV1
} from "../contracts/v1.js";
import {
  ExactMcpHttpForwarderV1,
  ForwardingDeniedV1,
  type DisposableExactForwarderV1Options
} from "../forwarding/disposable-forwarding-v1.js";
import {
  ProtectedCredentialBrokerV1,
  type ProtectedCredentialBindingV1
} from "../identity/protected-credential-broker-v1.js";
import type { HashiCorpVaultKvV2ProviderV1 } from "../identity/hashicorp-vault-provider-v1.js";
import type {
  ClientApprovedCallExecutorV1Options,
  ClientApprovedCallForwarderV1
} from "./client-tool-call-v1.js";

export interface ProtectedApprovalRuntimeDependenciesV1 {
  readonly issueCredentialLease: ClientApprovedCallExecutorV1Options["issueCredentialLease"];
  readonly forwarder: ClientApprovedCallForwarderV1;
  readonly executionTimeoutMs?: number;
}

export interface HashiCorpVaultApprovalRuntimeV1Options extends
  Omit<DisposableExactForwarderV1Options, "credentialVault"> {
  readonly secretManager: HashiCorpVaultKvV2ProviderV1;
  readonly credentialBindings: readonly ProtectedCredentialBindingV1[];
  readonly credentialBrokerClock?: () => Date;
  readonly credentialLeaseIdFactory?: () => string;
  readonly credentialFetchImplementation?: typeof fetch;
  readonly executionTimeoutMs?: number;
}

/**
 * Composes the approved Vault provider, non-exporting credential broker, exact HTTP
 * forwarder, and governed result boundary used by the protected approval runtime.
 */
export function createHashiCorpVaultApprovalRuntimeV1(
  options: HashiCorpVaultApprovalRuntimeV1Options
): ProtectedApprovalRuntimeDependenciesV1 {
  const broker = new ProtectedCredentialBrokerV1({
    secretManager: options.secretManager,
    bindings: options.credentialBindings,
    ...(options.credentialBrokerClock === undefined
      ? {}
      : { clock: options.credentialBrokerClock }),
    ...(options.credentialLeaseIdFactory === undefined
      ? {}
      : { leaseIdFactory: options.credentialLeaseIdFactory }),
    ...(options.credentialFetchImplementation === undefined
      ? {}
      : { fetchImplementation: options.credentialFetchImplementation })
  });
  const resolveBinding = (authorization: Parameters<typeof options.resolveCurrentRoute>[0]):
  DownstreamServerRouteBindingV1 => downstreamServerRouteBindingV1Schema.parse(
    options.resolveCurrentRoute(authorization)
  );
  const forwarder = new ExactMcpHttpForwarderV1({
    resolveCurrentRoute: options.resolveCurrentRoute,
    authenticateDownstream: options.authenticateDownstream,
    validateOutputSchema: options.validateOutputSchema,
    classifyResult: options.classifyResult,
    evaluateEgress: options.evaluateEgress,
    ...(options.knownSecretValues === undefined ? {} : { knownSecretValues: options.knownSecretValues }),
    ...(options.sensitiveFieldNames === undefined ? {} : { sensitiveFieldNames: options.sensitiveFieldNames }),
    ...(options.maxResultBytes === undefined ? {} : { maxResultBytes: options.maxResultBytes }),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.resultIdFactory === undefined ? {} : { resultIdFactory: options.resultIdFactory }),
    ...(options.provenanceIdFactory === undefined
      ? {}
      : { provenanceIdFactory: options.provenanceIdFactory }),
    ...(options.errorIdFactory === undefined ? {} : { errorIdFactory: options.errorIdFactory }),
    credentialVault: broker
  });

  return Object.freeze({
    issueCredentialLease: ({ call, authorization }: Parameters<
      ClientApprovedCallExecutorV1Options["issueCredentialLease"]
    >[0]) => {
      const binding = resolveBinding(authorization);
      if (binding.server.transport.kind !== "STREAMABLE_HTTP" ||
        binding.server.serverId !== authorization.serverId ||
        binding.route.routeId !== authorization.routeId ||
        binding.route.credentialAudienceId !== authorization.credentialAudienceId ||
        call.action.actionHash !== authorization.actionHash ||
        call.approval.approvalId !== authorization.approvalId) {
        throw new ForwardingDeniedV1();
      }
      return broker.issueLease(call.session, {
        credentialProfileId: binding.server.credentialAudience.credentialProfileId,
        audienceId: binding.route.credentialAudienceId,
        routeId: binding.route.routeId,
        endpointOrigin: new URL(binding.server.transport.endpoint).origin,
        approvalId: authorization.approvalId,
        actionHash: authorization.actionHash,
        forwardingAttemptId: authorization.forwardingAttemptId
      }).leaseId;
    },
    forwarder,
    ...(options.executionTimeoutMs === undefined
      ? {}
      : { executionTimeoutMs: options.executionTimeoutMs })
  });
}
