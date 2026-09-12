export interface GatewayActivityStatus {
  time: string;
  kind: "PROCESS_STARTED" | "MCP_REQUEST";
  outcome: "ACCEPT" | "REJECT" | "OBSERVED";
  detail: string;
}

export interface GatewayStatus {
  startedAt: string;
  requestsReceived: number;
  responses2xx: number;
  responses4xxPlus: number;
  downstreamToolsCalls: 0;
  forwardingEnabled: false;
  coverage: "UNPROTECTED";
  activity: GatewayActivityStatus[];
}

export interface DashboardStatus {
  generatedAt: string;
  phase: "Phase 2 - Production-Oriented MCP Gateway";
  coverage: "UNPROTECTED";
  implementation: "non-forwarding-discovery-adapter";
  gateway: GatewayStatus | null;
  features: {
    total: number;
    statuses: Partial<Record<"planned" | "in_progress" | "blocked" | "complete", number>>;
  };
  validation: {
    unit: { files: number; tests: number } | null;
    integration: { files: number; tests: number } | null;
    build: "PASS";
    lint: "PASS";
    typecheck: "PASS";
    featureValidation: "PASS";
  };
  securityControls: Array<{ name: string; state: string; detail: string }>;
  releaseGates: Array<{ name: string; state: string; detail: string }>;
  securityPipeline: Array<{ stage: string; outcome: string; detail: string }>;
  activity: Array<{ time: string; kind: string; outcome: string; detail: string }>;
  next: string;
}

export const dashboardStatusSchema: { parse(value: unknown): DashboardStatus };
export function parseGatewayStatus(value: unknown): GatewayStatus;
export function parseDashboardStatus(value: unknown): DashboardStatus;
export function readBoundedJsonResponse(response: Response, maxBytes?: number): Promise<unknown>;
export function buildDashboardStatus(
  root: string,
  options?: { gatewayStatus?: unknown }
): Promise<DashboardStatus>;
