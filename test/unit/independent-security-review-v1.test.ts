import { describe, expect, it } from "vitest";

import { computeCanonicalDigestV1 } from "../../src/action-normalizer/canonical-action-v1.js";
import {
  createIndependentSecurityReviewReportV1,
  independentSecurityReviewReportV1Schema,
  securityReviewFindingV1Schema
} from "../../src/evaluation/independent-security-review-v1.js";

const digest = (value: string): string => computeCanonicalDigestV1(value);

function input(): Parameters<typeof createIndependentSecurityReviewReportV1>[0] {
  return {
    reviewId: "review-001",
    sourceRevision: "revision-abc",
    sourceDigest: digest("source"),
    runtimeDigest: digest("runtime"),
    configurationDigest: digest("configuration"),
    reviewer: {
      reviewerId: "reviewer-001",
      reviewerName: "Independent Reviewer",
      organizationId: "review-org-001",
      organizationName: "Independent Review Organization",
      independenceDeclarationReference: "evidence/reviewer-independence.json",
      independenceDeclarationDigest: digest("independence")
    },
    reviewedScopes: ["runtime", "policy", "approval", "audit"],
    findings: [{
      findingId: "finding-001",
      title: "Missing deployment isolation evidence",
      severity: "HIGH" as const,
      status: "REMEDIATED" as const,
      affectedScope: ["deployment"],
      evidenceReference: "evidence/findings/finding-001.json",
      evidenceDigest: digest("finding"),
      remediationReference: "evidence/remediation/finding-001.json",
      remediationDigest: digest("remediation")
    }],
    disposition: "APPROVED" as const,
    completedAt: "2026-09-12T12:00:00.000Z",
    reviewEvidenceReference: "evidence/review/report.json",
    reviewEvidenceDigest: digest("review-evidence")
  };
}

function withoutRemediation(finding: Parameters<typeof createIndependentSecurityReviewReportV1>[0]["findings"][number]) {
  const { remediationReference, remediationDigest, ...remaining } = finding;
  void remediationReference;
  void remediationDigest;
  return remaining;
}

function firstFinding(value: ReturnType<typeof input>) {
  const finding = value.findings[0];
  if (finding === undefined) throw new Error("Review fixture requires a finding");
  return finding;
}

describe("independent security review evidence v1", () => {
  it("builds a source, runtime, configuration, finding, and remediation-bound report", () => {
    const report = createIndependentSecurityReviewReportV1(input());
    expect(report.validationScope).toBe("EVIDENCE_CONTRACT_ONLY");
    expect(report.disposition).toBe("APPROVED");
    const { reportDigest, ...material } = report;
    expect(reportDigest).toBe(computeCanonicalDigestV1(material));
  });

  it("requires remediation evidence and separately authorized residual risk", () => {
    const base = firstFinding(input());
    expect(securityReviewFindingV1Schema.safeParse(withoutRemediation(base)).success).toBe(false);
    expect(securityReviewFindingV1Schema.safeParse({
      ...withoutRemediation(base), status: "ACCEPTED_RISK"
    }).success).toBe(false);

    const reportInput = input();
    reportInput.findings = [{
      ...withoutRemediation(base),
      status: "ACCEPTED_RISK",
      residualRiskAuthorization: {
        riskOwnerId: "risk-owner-001",
        authorizationReference: "evidence/risk/finding-001.json",
        authorizationDigest: digest("risk-authorization"),
        authorizedAt: "2026-09-12T11:59:00.000Z"
      }
    }];
    reportInput.disposition = "APPROVED_WITH_RESIDUAL_RISK";
    expect(createIndependentSecurityReviewReportV1(reportInput).disposition)
      .toBe("APPROVED_WITH_RESIDUAL_RISK");
  });

  it("rejects reviewer self-authorization, open-finding approval, and digest substitution", () => {
    const selfAuthorized = input();
    const base = firstFinding(selfAuthorized);
    selfAuthorized.findings = [{
      ...withoutRemediation(base),
      status: "ACCEPTED_RISK",
      residualRiskAuthorization: {
        riskOwnerId: selfAuthorized.reviewer.reviewerId,
        authorizationReference: "evidence/risk/finding-001.json",
        authorizationDigest: digest("risk-authorization"),
        authorizedAt: "2026-09-12T11:59:00.000Z"
      }
    }];
    selfAuthorized.disposition = "APPROVED_WITH_RESIDUAL_RISK";
    expect(() => createIndependentSecurityReviewReportV1(selfAuthorized)).toThrow(/reviewer/u);

    const open = input();
    open.findings = [{ ...withoutRemediation(firstFinding(open)), status: "OPEN" }];
    expect(() => createIndependentSecurityReviewReportV1(open)).toThrow(/disposition/u);

    const valid = createIndependentSecurityReviewReportV1(input());
    expect(independentSecurityReviewReportV1Schema.safeParse({
      ...valid, sourceDigest: digest("substituted")
    }).success).toBe(false);
  });
});
