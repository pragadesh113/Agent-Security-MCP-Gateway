export const gatewayScaffoldStatus = Object.freeze({
  phase: "phase-2-mcp-gateway",
  implementation: "non-forwarding-discovery-adapter",
  coverage: "UNPROTECTED",
  acceptsLifecycleTraffic: true,
  protectedForwardingEnabled: false
} as const);

export type GatewayScaffoldStatus = typeof gatewayScaffoldStatus;

export {
  coverageStateV1Schema,
  downstreamServerRouteBindingV1Schema,
  downstreamServerV1Schema,
  gatewayClientV1Schema,
  gatewaySessionQuotaLimitsV1Schema,
  gatewaySessionV1Schema,
  toolRouteSetV1Schema,
  toolRouteV1Schema
} from "./contracts/v1.js";

export type {
  CoverageStateV1,
  DownstreamServerRouteBindingV1,
  DownstreamServerV1,
  GatewayClientV1,
  GatewaySessionQuotaLimitsV1,
  GatewaySessionV1,
  ToolRouteV1
} from "./contracts/v1.js";

export {
  approvalV1Schema,
  canonicalActionDecisionBindingV1Schema,
  canonicalActionV1Schema,
  downstreamProvenanceV1Schema,
  downstreamResultV1Schema,
  executionOutcomeV1Schema,
  policyDecisionV1Schema,
  requestOutcomeTrajectoryV1Schema
} from "./contracts/trajectory-v1.js";

export type {
  ApprovalV1,
  CanonicalActionV1,
  DownstreamProvenanceV1,
  DownstreamResultV1,
  ExecutionOutcomeV1,
  PolicyDecisionV1,
  RequestOutcomeTrajectoryV1
} from "./contracts/trajectory-v1.js";

export {
  awarenessV1Schema,
  boundedProtocolJsonObjectV1Schema,
  boundedProtocolJsonV1Schema,
  discoveryResultV1Schema,
  gatewayErrorV1Schema,
  rawToolResultV1Schema,
  toolCallRequestV1Schema,
  untrustedProtocolJsonShapeGuardV1Schema,
  versionedBoundaryEnvelopeV1Schema
} from "./contracts/boundary-v1.js";

export type {
  AwarenessV1,
  DiscoveryResultV1,
  GatewayErrorV1,
  RawToolResultV1,
  ToolCallRequestV1,
  VersionedBoundaryEnvelopeV1
} from "./contracts/boundary-v1.js";

export {
  closeMcpLifecycleV1,
  initialMcpLifecycleStateV1,
  initializedNotificationV1Schema,
  initializeRequestV1Schema,
  initializeResponseV1Schema,
  jsonRpcErrorResponseV1Schema,
  lifecycleResponseV1Schema,
  mcpLifecycleStateV1Schema,
  pingRequestV1Schema,
  selectedMcpProtocolVersionV1,
  supportedMcpProtocolVersionsV1,
  transitionMcpLifecycleV1
} from "./protocol/initialization-v1.js";

export type {
  LifecycleResponseV1,
  McpLifecycleOptionsV1,
  McpLifecycleStateV1,
  McpLifecycleTransitionV1
} from "./protocol/initialization-v1.js";

export { createInitializationHttpAppV1 } from "./transport/streamable-http-initialization-v1.js";

export type { InitializationHttpAppV1Options } from "./transport/streamable-http-initialization-v1.js";

export {
  authenticatedClientPrincipalV1Schema,
  authenticatedSessionIdentityBindingV1Schema,
  bindAuthenticatedIdentityToSessionV1,
  principalHasSameSubjectV1,
  principalMatchesSessionBindingV1
} from "./identity/client-authentication-v1.js";

export {
  CanonicalActionNormalizerV1,
  CanonicalizationDeniedV1,
  canonicalActionAnalysisV1Schema,
  canonicalResourceCandidateV1Schema,
  computeCanonicalDigestV1,
  computeCanonicalJsonByteLengthV1,
  normalizeCanonicalReferenceV1
} from "./action-normalizer/canonical-action-v1.js";

export type {
  CanonicalActionAnalysisV1,
  CanonicalActionNormalizerV1Options,
  CanonicalActionResolverV1,
  CanonicalResourceCandidateV1
} from "./action-normalizer/canonical-action-v1.js";

export {
  DeterministicPolicyEngineV1,
  classifyCanonicalRiskTierV1,
  createConstraintV1,
  deterministicPolicyRuleV1Schema,
  policyAdvisoryV1Schema
} from "./policy-engine/deterministic-policy-v1.js";

export type {
  DeterministicPolicyEngineV1Options,
  DeterministicPolicyRuleV1,
  PolicyAdvisoryV1
} from "./policy-engine/deterministic-policy-v1.js";

export {
  ApprovalDeniedV1,
  DisposableApprovalServiceV1,
  approvalAuditEventV1Schema,
  approvalAuditReaderAuthorityV1Schema,
  approvedForwardingAuthorizationV1Schema,
  humanApprovalDecisionV1Schema
} from "./approval/disposable-approval-v1.js";

export type {
  ApprovalAuditEventV1,
  ApprovalAuditReaderAuthorityV1,
  ApprovedForwardingAuthorizationV1,
  DisposableApprovalServiceV1Options,
  HumanApprovalDecisionV1
} from "./approval/disposable-approval-v1.js";

export {
  DisposableProtocolGuardV1,
  ProtocolGuardDeniedV1,
  protocolGuardAuditEventV1Schema,
  protocolGuardLimitsV1Schema,
  protocolOperationRequestV1Schema
} from "./protocol/protocol-guard-v1.js";

export type {
  DisposableProtocolGuardV1Options,
  GuardedOperationResultV1,
  GuardedOperationToolsV1,
  ProtocolGuardAuditEventV1,
  ProtocolGuardDenialReasonV1,
  ProtocolGuardLimitsV1,
  ProtocolOperationCheckpointV1,
  ProtocolOperationLeaseV1,
  ProtocolOperationRequestV1
} from "./protocol/protocol-guard-v1.js";

export {
  CredentialAccessDeniedV1,
  DisposableCredentialVaultV1,
  credentialLeaseV1Schema,
  credentialProfileV1Schema
} from "./identity/credential-vault-v1.js";

export type {
  CredentialLeaseV1,
  CredentialProfileV1,
  DisposableCredentialVaultV1Options
} from "./identity/credential-vault-v1.js";

export {
  DisposableSessionStateRepositoryV1,
  SessionAccessDeniedV1,
  sessionCompartmentV1Schema
} from "./identity/session-isolation-v1.js";

export {
  DisposableDownstreamRegistryV1,
  DownstreamRegistryDeniedV1,
  authenticatedDownstreamPrincipalV1Schema,
  computeRegistryDigestV1,
  downstreamDiscoveryObservationV1Schema,
  downstreamRegistrationV1Schema,
  downstreamRegistryAuditEventV1Schema,
  routeAdministratorAuthorityV1Schema
} from "./routing/downstream-registry-v1.js";

export type {
  AuthenticatedDownstreamPrincipalV1,
  DisposableDownstreamRegistryV1Options,
  DownstreamAuthenticationAttemptV1,
  DownstreamAuthenticatorV1,
  DownstreamDiscoveryObservationV1,
  DownstreamRegistrationV1,
  DownstreamRegistryAuditEventV1,
  RouteAdministratorAuthorityV1,
  RouteAuthorizationContextV1,
  RouteAuthorizerV1
} from "./routing/downstream-registry-v1.js";

export type {
  SessionAdministrativeSnapshotV1,
  SessionCompartmentV1,
  SessionInvalidationSinkV1
} from "./identity/session-isolation-v1.js";

export type {
  AuthenticatedClientPrincipalV1,
  AuthenticatedSessionIdentityBindingV1,
  ClientAuthenticationAttemptV1,
  ClientAuthenticatorV1
} from "./identity/client-authentication-v1.js";

export {
  ProtectedClientIdentityProviderV1,
  ProtectedClientIdentityUnavailableV1,
  TLS_CLIENT_AUTH_EKU_OID_V1,
  normalizeTlsCertificateFingerprintSha256V1,
  protectedClientCredentialRecordV1Schema,
  trustedTlsPeerFactsV1Schema
} from "./identity/protected-client-identity-v1.js";
export type {
  ProtectedClientCredentialRecordV1,
  ProtectedClientCredentialStoreV1,
  ProtectedClientIdentityProviderV1Options,
  TrustedTlsPeerFactsV1
} from "./identity/protected-client-identity-v1.js";

export {
  ProtectedCredentialBrokerV1,
  ProtectedCredentialDeniedV1,
  approvedSecretManagerDescriptorV1Schema,
  protectedCredentialBindingV1Schema,
  protectedCredentialLeaseV1Schema
} from "./identity/protected-credential-broker-v1.js";
export type {
  ApprovedSecretManagerDescriptorV1,
  ApprovedSecretManagerProviderV1,
  ProtectedCredentialBindingV1,
  ProtectedCredentialBrokerV1Options,
  ProtectedCredentialDenialReasonV1,
  ProtectedCredentialLeaseV1,
  SecretManagerExactRevisionV1
} from "./identity/protected-credential-broker-v1.js";

export {
  HashiCorpVaultKvV2ProviderV1,
  vaultReferenceV1Schema
} from "./identity/hashicorp-vault-provider-v1.js";
export type {
  HashiCorpVaultKvV2ProviderV1Options
} from "./identity/hashicorp-vault-provider-v1.js";

export {
  RequiredAnalyzerRegistryV1,
  RequiredAnalyzerConfigurationErrorV1,
  createCompleteRequiredAnalyzerRegistryV1,
  quarantinedAnalyzerFindingV1Schema,
  requiredAnalyzerCategoriesV1,
  requiredAnalyzerCategoryV1Schema,
  requiredAnalyzerFindingV1Schema,
  requiredAnalyzerRequestV1Schema
} from "./action-normalizer/required-analyzers-v1.js";
export type {
  QuarantinedAnalyzerFindingV1,
  CompleteRequiredAnalyzerSetV1,
  RequiredAnalyzerCategoryV1,
  RequiredAnalyzerFindingV1,
  RequiredAnalyzerOutcomeV1,
  RequiredAnalyzerRequestV1,
  RequiredAnalyzerSetV1,
  RequiredAnalyzerV1
} from "./action-normalizer/required-analyzers-v1.js";

export {
  createOperationalTrialEvidenceBundleV1,
  operationalHostV1Schema,
  operationalTrialEvidenceBundleV1Schema,
  operationalTrialEvidenceV1Schema,
  operationalTrialReproductionV1Schema
} from "./evaluation/operational-trial-evidence-v1.js";
export type {
  OperationalHostV1,
  OperationalTrialEvidenceBundleV1,
  OperationalTrialEvidenceV1,
  OperationalTrialReproductionV1
} from "./evaluation/operational-trial-evidence-v1.js";

export {
  IndependentHostEvidenceGateV1,
  authenticatedHostAdapterEvidenceV1Schema,
  independentHostEvidenceReportV1Schema,
  independentHostWorkflowEvidenceV1Schema,
  namedIndependentHostEvidenceV1Schema
} from "./evaluation/independent-host-evidence-v1.js";
export type {
  AuthenticatedHostAdapterEvidenceV1,
  IndependentHostEvidenceReportV1,
  IndependentHostWorkflowEvidenceV1,
  NamedIndependentHostEvidenceV1
} from "./evaluation/independent-host-evidence-v1.js";

export {
  createIndependentSecurityReviewReportV1,
  independentReviewerV1Schema,
  independentSecurityReviewReportV1Schema,
  securityReviewFindingV1Schema
} from "./evaluation/independent-security-review-v1.js";
export type {
  IndependentReviewerV1,
  IndependentSecurityReviewReportV1,
  SecurityReviewFindingV1
} from "./evaluation/independent-security-review-v1.js";

export {
  DisposableExactForwarderV1,
  ForwardingDeniedV1,
  mediatedForwardingResultV1Schema
} from "./forwarding/disposable-forwarding-v1.js";

export type {
  DisposableExactForwarderV1Options,
  MediatedForwardingResultV1,
  ResultClassificationV1,
  ResultDispositionV1
} from "./forwarding/disposable-forwarding-v1.js";

export type { CredentialedMcpHttpResponseV1 } from "./identity/credential-vault-v1.js";

export { runForwardMigrationsV1 } from "./persistence/migrations-v1.js";
export type { AppliedMigrationV1 } from "./persistence/migrations-v1.js";

export {
  PostgresProtectedClientIdentityStoreV1,
  ProtectedIdentityPersistenceDeniedV1
} from "./persistence/postgres-identity-store-v1.js";
export type {
  PostgresProtectedIdentityConfigV1,
  ProtectedClientIdentityAuditEventV1,
  ProtectedIdentityMutationContextV1
} from "./persistence/postgres-identity-store-v1.js";

export {
  PostgresProtectedAdministrationStoreV1,
  ProtectedAdministrationDeniedV1,
  protectedAdministrationRecordV1Schema
} from "./persistence/postgres-administration-store-v1.js";
export type {
  PostgresProtectedAdministrationConfigV1,
  ProtectedAdministrationAuditEventV1,
  ProtectedAdministrationKindV1,
  ProtectedAdministrationRecordV1,
  ProtectedAdministratorAuthorizerV1
} from "./persistence/postgres-administration-store-v1.js";

export {
  PersistenceDeniedV1,
  PersistenceUnavailableV1,
  PostgresTrajectoryStoreV1,
  SecretPersistenceDeniedV1,
  persistedSecurityEventV1Schema,
  postgresPersistenceConfigV1Schema,
  securityEventInputV1Schema
} from "./persistence/postgres-trajectory-store-v1.js";

export type {
  PersistedSecurityEventV1,
  PostgresPersistenceConfigV1,
  SecurityEventInputV1
} from "./persistence/postgres-trajectory-store-v1.js";

export {
  CoverageAssessmentDeniedV1,
  CoverageBoundPolicyEvaluatorV1,
  ExclusiveMediationMonitorV1,
  coverageAssuranceV1Schema,
  coverageEvidenceStatusV1Schema,
  coverageEvidenceV1Schema,
  coveragePathKindV1Schema,
  coverageScopeMatchesActionV1,
  coverageScopeV1Schema,
  coverageVerifierClassV1Schema,
  exclusiveMediationAssessmentV1Schema,
  mediationGuaranteeV1Schema
} from "./coverage/exclusive-mediation-v1.js";

export {
  ApprovalFatigueRecorderV1,
  TrustworthyInterfaceBuilderV1,
  approvalFatigueEventV1Schema,
  approvalFatigueMetricsV1Schema,
  trustworthyActionInterfaceV1Schema
} from "./interfaces/trustworthy-interface-v1.js";

export {
  SeededSecurityEvaluationHarnessV1,
  assertCompleteEvaluationCatalogV1,
  attackClassV1Schema,
  createRequiredEvaluationCatalogV1,
  evaluationReportV1Schema,
  evaluationScenarioV1Schema,
  evaluationSuiteV1Schema,
  evaluationTrialObservationV1Schema
} from "./evaluation/seeded-harness-v1.js";

export {
  MultiHostValidationHarnessV1,
  bypassInventoryEntryV1Schema,
  hostWorkflowObservationV1Schema,
  multiHostValidationReportV1Schema
} from "./evaluation/multi-host-validation-v1.js";

export {
  DEFAULT_TRUST_PROMOTION_THRESHOLDS_V1,
  DynamicTrustControllerV1,
  boundedTrustCandidateV1Schema,
  buildDynamicTrustExperimentReportV1,
  dynamicTrustExperimentReportV1Schema,
  trustFreezeSignalV1Schema,
  trustPromotionThresholdsV1Schema,
  trustScopeV1Schema,
  trustTrialObservationV1Schema,
  verifiedPositiveTrustEvidenceV1Schema
} from "./trust/dynamic-trust-v1.js";
export type {
  BoundedTrustCandidateV1,
  DynamicTrustExperimentReportV1,
  TrustFreezeSignalV1,
  TrustPromotionThresholdsV1,
  TrustScopeV1,
  TrustTrialObservationV1,
  VerifiedPositiveTrustEvidenceV1
} from "./trust/dynamic-trust-v1.js";

export type {
  HostWorkflowObservationV1,
  McpHostAdapterV1,
  MultiHostValidationReportV1
} from "./evaluation/multi-host-validation-v1.js";

export type {
  EvaluationReportV1,
  EvaluationScenarioV1,
  EvaluationTrialObservationV1,
  SeededTrialContextV1,
  SeededTrialExecutorV1
} from "./evaluation/seeded-harness-v1.js";

export type {
  ApprovalFatigueMetricsV1,
  ApprovalFatigueEventV1,
  TrustworthyActionInterfaceV1,
  TrustworthyInterfaceBuilderV1Options
} from "./interfaces/trustworthy-interface-v1.js";

export type {
  CoverageEvidenceProbeV1,
  CoverageAssuranceV1,
  CoverageEvidenceStatusV1,
  CoverageEvidenceV1,
  CoveragePathKindV1,
  CoverageScopeV1,
  CoverageVerifierClassV1,
  ExclusiveMediationAssessmentV1,
  ExclusiveMediationMonitorV1Options,
  MediationGuaranteeV1
} from "./coverage/exclusive-mediation-v1.js";

export {
  AdvisorySupervisorV1,
  SupervisorAuditUnavailableV1,
  supervisorAssessmentAuditV1Schema,
  supervisorProviderOutputV1Schema,
  supervisorProviderRequestV1Schema,
  supervisorUntrustedFragmentInputV1Schema
} from "./supervisor/advisory-supervisor-v1.js";

export {
  ClientApprovedCallExecutorV1,
  ClientToolCallCoordinatorV1
} from "./runtime/client-tool-call-v1.js";
export type {
  ApprovedClientToolCallV1,
  ClientApprovedCallExecutorV1Options,
  ClientApprovedCallForwarderV1,
  ClientApprovedCallStoreV1,
  ClientToolCallCoordinatorV1Options,
  ClientToolCallDecisionResultV1,
  ClientToolCallDecisionStoreV1,
  ClientToolCallInputV1,
  ResolvedClientToolRouteV1
} from "./runtime/client-tool-call-v1.js";
export type {
  AdvisorySupervisorProviderV1,
  AdvisorySupervisorV1Options,
  SupervisorAssessmentAuditV1,
  SupervisorAuditSinkV1,
  SupervisorProviderOutputV1,
  SupervisorProviderRequestV1,
  SupervisorUntrustedFragmentInputV1
} from "./supervisor/advisory-supervisor-v1.js";
