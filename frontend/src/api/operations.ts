import { api } from "./http";

export interface EDRAgent {
  id: string;
  agent_id: string;
  hostname: string;
  os_type: string;
  ip_address: string;
  status: string;
  is_isolated: boolean;
  version: string;
  last_heartbeat_at: string;
  device_id: string | null;
  created_at: string;
}

export interface EDREvent {
  id: string;
  agent_id: string;
  event_type: string;
  severity: string;
  source: string;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface BlockedIP {
  id: string;
  ip_address: string;
  reason: string | null;
  blocked_until: string | null;
  permanent: boolean;
  created_at: string;
}

export interface SimulatorScenario {
  id: string;
  name: string;
  description: string;
  category: string;
  expected_score_range: string;
  expected_action: string;
  severity: string;
  steps_count: number;
}

export interface SimulationResult {
  scenario_id: string;
  scenario_name: string;
  final_score: number;
  risk_level: string;
  action: string;
  timeline: Array<Record<string, unknown>>;
  alerts_generated: Array<Record<string, unknown>>;
}

export interface OAuthProvider {
  id?: string;
  name?: string;
  provider?: string;
  display_name?: string;
  type?: string;
}

export interface HealthStatus {
  status: "ok" | "degraded";
  app: string;
  version: string;
  environment: string;
  database: string;
  database_reachable: boolean;
  cache: string;
  tables: number;
  providers: Record<string, string>;
}

export interface SCIMUser {
  id: string;
  userName: string;
  displayName?: string;
  active: boolean;
  emails?: Array<{ value: string; primary?: boolean }>;
  roles?: Array<{ value: string }>;
  meta?: { lastModified?: string };
}

export interface SCIMListResponse<T> {
  totalResults: number;
  itemsPerPage: number;
  startIndex: number;
  Resources: T[];
}

export const getEDRAgents = () => api.get<EDRAgent[]>("/api/edr/agents").then((r) => r.data);
export const getEDREvents = (params = "") => api.get<EDREvent[]>(`/api/edr/events${params}`).then((r) => r.data);
export const isolateEDRAgent = (agentId: string, reason: string) => api.post<EDRAgent>(`/api/edr/agents/${encodeURIComponent(agentId)}/isolate`, { reason }).then((r) => r.data);
export const restoreEDRAgent = (agentId: string) => api.post<EDRAgent>(`/api/edr/agents/${encodeURIComponent(agentId)}/unisolate`).then((r) => r.data);

export const getBlockedIPs = () => api.get<BlockedIP[]>("/api/blocked-ips").then((r) => r.data);
export const blockIP = (ip_address: string, reason: string, duration_minutes: number | null) => api.post<BlockedIP>("/api/blocked-ips", { ip_address, reason, duration_minutes }).then((r) => r.data);
export const unblockIP = (address: string) => api.delete(`/api/blocked-ips/${encodeURIComponent(address)}`);

export const getSimulatorScenarios = () => api.get<SimulatorScenario[]>("/api/simulator/scenarios").then((r) => r.data);
export const runSimulatorScenario = (scenarioId: string) => api.post<SimulationResult>(`/api/simulator/run/${scenarioId}`).then((r) => r.data);
export const resetSimulator = () => api.post<{ status: string; message: string }>("/api/simulator/reset").then((r) => r.data);

export const getOAuthProviders = () => api.get<OAuthProvider[]>("/api/auth/oauth/providers").then((r) => r.data);
export const getSCIMUsers = () => api.get<SCIMListResponse<SCIMUser>>("/scim/v2/Users?count=25").then((r) => r.data);
export const getSCIMGroups = () => api.get<SCIMListResponse<Record<string, unknown>>>("/scim/v2/Groups").then((r) => r.data);
export const getHealthStatus = () => api.get<HealthStatus>("/health").then((r) => r.data);

export const generateIncidentNarrative = (payload: Record<string, unknown>) => api.post<{ narrative: string; model: string; username: string; risk_score: number }>("/api/ai/narrate-incident", payload).then((r) => r.data);
export const synthesizeBaseline = (role: string, department: string, permissions: string[]) => api.post<Record<string, unknown>>("/api/ai/synthesize-baseline", { role, department, permissions }).then((r) => r.data);


export interface SHAPFeatureAttribution {
  feature: string;
  description: string;
  shap_value: number;
  direction: string;
  impact_percentage: number;
}

export interface SHAPExplanationResult {
  anomaly_score: number;
  method: string;
  shap_values: Record<string, number>;
  top_anomaly_drivers: SHAPFeatureAttribution[];
  top_mitigating_factors: SHAPFeatureAttribution[];
  all_attributions: SHAPFeatureAttribution[];
}

export const explainAnomaly = (features: Record<string, number>, user_id?: string) =>
  api.post<SHAPExplanationResult>("/api/ai/explain-anomaly", { features, user_id }).then((r) => r.data);

export interface SyntheticScenarioMeta {
  id: string;
  name: string;
  category: string;
  description: string;
  expected_anomaly_score_range: string;
  expected_risk_level: string;
  expected_action: string;
  features: Record<string, number>;
}

export interface VerificationGate {
  gate_name: string;
  passed: boolean;
  status: "PASS" | "FAIL";
  details: string;
}

export interface ScenarioRunResult {
  scenario: {
    id: string;
    name: string;
    category: string;
    description: string;
  };
  inference: {
    anomaly_score: number;
    model_name: string;
    duration_ms: number;
    features: Record<string, number>;
  };
  shap_explanation: {
    method: string;
    duration_ms: number;
    top_anomaly_drivers: Array<{
      feature: string;
      impact_signed: number;
      impact_percent: string;
      raw_value: number;
      description: string;
    }>;
    top_mitigating_factors: Array<{
      feature: string;
      impact_signed: number;
      impact_percent: string;
      raw_value: number;
      description: string;
    }>;
    feature_attributions: Array<{
      feature: string;
      impact_signed: number;
      impact_percent: string;
      raw_value: number;
      description: string;
    }>;
  };
  policy_decision: {
    trust_score: number;
    risk_score: number;
    risk_level: string;
    action: string;
    overrides_triggered: string[];
    factor_penalties: Record<string, number>;
  };
  audit_verification: {
    seq: number;
    record_hash: string;
    prev_hash: string;
    payload_hash: string;
    timestamp: string;
    chain_valid: boolean;
    verification_algorithm: string;
  };
  verification_gates: {
    gate_1_model_inference: VerificationGate;
    gate_2_shap_explanation: VerificationGate;
    gate_3_policy_decision: VerificationGate;
    gate_4_audit_persistence: VerificationGate;
  };
  overall_result: "PASS" | "FAIL";
  total_latency_ms: number;
}

export const getSyntheticScenarios = () =>
  api.get<SyntheticScenarioMeta[]>("/api/ai/scenario-runner/scenarios").then((r) => r.data);

export const runAnomalyScenario = (scenarioId?: string, customFeatures?: Record<string, number>) =>
  api.post<ScenarioRunResult>("/api/ai/scenario-runner/run", { scenario_id: scenarioId, custom_features: customFeatures }).then((r) => r.data);
