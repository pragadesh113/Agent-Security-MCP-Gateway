import { canonicalActionAnalysisV1Schema, type CanonicalActionResolverV1 } from "./canonical-action-v1.js";
import { type WorkspaceFileResolverV1 } from "./workspace-file-resolver-v1.js";

/** Opt-in research adapter. It is not wired to any protected runtime entrypoint. */
export function createWorkspaceFileActionResolverV1(options: {
  readonly resolver: WorkspaceFileResolverV1;
  readonly publicResourceIds: ReadonlySet<string>;
}): CanonicalActionResolverV1 {
  const publicIds = new Set(options.publicResourceIds);
  return (context) => {
    if (context.binding.route.environment !== "TEST" || context.binding.route.resourceMapping.resourceClass !== "FILESYSTEM") {
      throw new Error("Workspace research resolver requires a test filesystem route");
    }
    const resolution = options.resolver.resolve({
      schemaVersion: "1.0.0", tool: context.binding.route.toolName, arguments: context.arguments
    });
    if (resolution.status !== "RESOLVED") throw new Error("Workspace semantics remain unresolved");
    const classification = publicIds.has(resolution.resource.resourceId) ? "PUBLIC" : "UNKNOWN";
    return canonicalActionAnalysisV1Schema.parse({
      schemaVersion: "1.0.0", parserId: context.binding.route.resourceMapping.resolverId,
      parserVersion: "1.0.0", status: "FULL",
      resources: [{
        resourceId: resolution.resource.resourceId, resourceClass: "FILESYSTEM",
        // State enters the existing action hash without treating a lexical path as identity.
        reference: `workspace:${resolution.resource.resourceId}:${resolution.resource.stateDigest}`,
        referencePlatform: "OPAQUE", classification
      }],
      effect: resolution.effect, environment: "TEST",
      dataFlow: { direction: "NONE", classifications: [classification], externalDestination: false, destinationId: null },
      reversibility: resolution.effect === "READ" ? "NOT_APPLICABLE" : "UNKNOWN",
      influences: ["USER_INPUT"]
    });
  };
}
