import type { DashboardStatus, GatewayStatus } from "./dashboard-status.mjs";

export interface LocalEvidence {
  schemaVersion: "1.0.0";
  capturedAt: string;
  scope: "DISPOSABLE_LOCAL_ONLY";
  gateway: GatewayStatus;
  dashboard: Pick<DashboardStatus, "generatedAt" | "coverage" | "features" | "validation" | "releaseGates">;
  releaseManifest: unknown;
}

export function buildLocalEvidence(input: {
  gateway: unknown;
  dashboard: unknown;
  releaseManifest: unknown;
  capturedAt?: string;
}): LocalEvidence;
export function captureLocalEvidence(): Promise<void>;
