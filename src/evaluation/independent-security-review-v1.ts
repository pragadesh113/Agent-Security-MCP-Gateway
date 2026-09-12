import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import { identifierV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";

const digestV1Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const evidenceReferenceV1Schema = z.string().trim().min(1).max(2_048);

export const independentReviewerV1Schema = z.object({
  reviewerId: identifierV1Schema,
  reviewerName: z.string().trim().min(1).max(128),
  organizationId: identifierV1Schema,
  organizationName: z.string().trim().min(1).max(128),
  independenceDeclarationReference: evidenceReferenceV1Schema,
  independenceDeclarationDigest: digestV1Schema
}).strict();

export const securityReviewFindingV1Schema = z.object({
  findingId: identifierV1Schema,
  title: z.string().trim().min(1).max(256),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]),
  status: z.enum(["OPEN", "REMEDIATED", "ACCEPTED_RISK"]),
  affectedScope: z.array(identifierV1Schema).min(1).max(64),
  evidenceReference: evidenceReferenceV1Schema,
  evidenceDigest: digestV1Schema,
  remediationReference: evidenceReferenceV1Schema.optional(),
  remediationDigest: digestV1Schema.optional(),
  residualRiskAuthorization: z.object({
    riskOwnerId: identifierV1Schema,
    authorizationReference: evidenceReferenceV1Schema,
    authorizationDigest: digestV1Schema,
    authorizedAt: utcTimestampV1Schema
  }).strict().optional()
}).strict().superRefine((finding, context) => {
  const hasRemediation = finding.remediationReference !== undefined &&
    finding.remediationDigest !== undefined;
  if (finding.status === "REMEDIATED" && !hasRemediation) {
    context.addIssue({ code: "custom", path: ["remediationReference"],
      message: "Remediated findings require bound remediation evidence" });
  }
  if (finding.status !== "REMEDIATED" &&
    (finding.remediationReference !== undefined || finding.remediationDigest !== undefined)) {
    context.addIssue({ code: "custom", path: ["remediationReference"],
      message: "Only remediated findings may carry remediation evidence" });
  }
  if (finding.status === "ACCEPTED_RISK" && finding.residualRiskAuthorization === undefined) {
    context.addIssue({ code: "custom", path: ["residualRiskAuthorization"],
      message: "Accepted residual risk requires explicit owner authorization" });
  }
  if (finding.status !== "ACCEPTED_RISK" && finding.residualRiskAuthorization !== undefined) {
    context.addIssue({ code: "custom", path: ["residualRiskAuthorization"],
      message: "Residual-risk authorization is valid only for accepted risk" });
  }
});

export const independentSecurityReviewReportV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  reviewId: identifierV1Schema,
  validationScope: z.literal("EVIDENCE_CONTRACT_ONLY"),
  sourceRevision: z.string().trim().min(1).max(256),
  sourceDigest: digestV1Schema,
  runtimeDigest: digestV1Schema,
  configurationDigest: digestV1Schema,
  reviewer: independentReviewerV1Schema,
  reviewedScopes: z.array(identifierV1Schema).min(1).max(128),
  findings: z.array(securityReviewFindingV1Schema).max(10_000),
  disposition: z.enum(["APPROVED", "APPROVED_WITH_RESIDUAL_RISK", "REJECTED"]),
  completedAt: utcTimestampV1Schema,
  reviewEvidenceReference: evidenceReferenceV1Schema,
  reviewEvidenceDigest: digestV1Schema,
  reportDigest: digestV1Schema
}).strict().superRefine((report, context) => {
  const openMaterial = report.findings.some((finding) => finding.status === "OPEN" &&
    finding.severity !== "INFORMATIONAL");
  const acceptedRisk = report.findings.some((finding) => finding.status === "ACCEPTED_RISK");
  const expectedDisposition = openMaterial ? "REJECTED" :
    acceptedRisk ? "APPROVED_WITH_RESIDUAL_RISK" : "APPROVED";
  if (report.disposition !== expectedDisposition) {
    context.addIssue({ code: "custom", path: ["disposition"],
      message: "Review disposition does not match finding states" });
  }
  for (const finding of report.findings) {
    if (finding.residualRiskAuthorization?.riskOwnerId === report.reviewer.reviewerId) {
      context.addIssue({ code: "custom", path: ["findings"],
        message: "The independent reviewer cannot authorize residual risk" });
    }
  }
  const { reportDigest, ...digestInput } = report;
  if (reportDigest !== computeCanonicalDigestV1(digestInput)) {
    context.addIssue({ code: "custom", path: ["reportDigest"],
      message: "Independent security review report digest does not match" });
  }
});

export type IndependentReviewerV1 = z.infer<typeof independentReviewerV1Schema>;
export type SecurityReviewFindingV1 = z.infer<typeof securityReviewFindingV1Schema>;
export type IndependentSecurityReviewReportV1 = z.infer<
  typeof independentSecurityReviewReportV1Schema
>;

export function createIndependentSecurityReviewReportV1(input: Omit<
IndependentSecurityReviewReportV1, "schemaVersion" | "validationScope" | "reportDigest"
>): IndependentSecurityReviewReportV1 {
  const material = {
    schemaVersion: "1.0.0" as const,
    validationScope: "EVIDENCE_CONTRACT_ONLY" as const,
    ...input
  };
  return independentSecurityReviewReportV1Schema.parse({
    ...material,
    reportDigest: computeCanonicalDigestV1(material)
  });
}
