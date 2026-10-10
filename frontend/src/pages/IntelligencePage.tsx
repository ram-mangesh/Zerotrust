import { useEffect, useState } from "react";
import { getAlerts, type AlertRow } from "../api/client";
import { apiErrorMessage } from "../api/http";
import {
  generateIncidentNarrative,
  getSyntheticScenarios,
  runAnomalyScenario,
  synthesizeBaseline,
  type ScenarioRunResult,
  type SyntheticScenarioMeta,
} from "../api/operations";
import Page, { Card, Empty, RiskChip } from "../components/layout/Page";

const TABS = [
  "Anomaly scenario runner",
  "Incident investigation",
  "Behavioral baseline synthesis",
] as const;
type Tab = (typeof TABS)[number];

export default function IntelligencePage() {
  const [tab, setTab] = useState<Tab>("Anomaly scenario runner");
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertRow | null>(null);
  const [narrative, setNarrative] = useState("");
  const [model, setModel] = useState("");
  const [baseline, setBaseline] = useState<Record<string, unknown> | null>(null);

  // Scenario Runner State
  const [scenarios, setScenarios] = useState<SyntheticScenarioMeta[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("baseline_normal");
  const [scenarioResult, setScenarioResult] = useState<ScenarioRunResult | null>(null);
  const [customRpm, setCustomRpm] = useState<string>("");
  const [customVpn, setCustomVpn] = useState<boolean>(false);
  const [customVelocity, setCustomVelocity] = useState<string>("");

  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    void getAlerts("?limit=30").then((d) => {
      setAlerts(d.alerts);
      setSelectedAlert(d.alerts[0] ?? null);
    });
    void getSyntheticScenarios().then((list) => {
      setScenarios(list);
      if (list.length > 0 && !selectedScenarioId) {
        setSelectedScenarioId(list[0].id);
      }
    });
  }, [selectedScenarioId]);

  async function handleRunScenario(id?: string) {
    const targetId = id || selectedScenarioId;
    setBusy("scenario");
    setError("");
    try {
      const customOverrides: Record<string, number> = {};
      if (customRpm) customOverrides.requests_per_minute = parseFloat(customRpm);
      if (customVelocity) customOverrides.travel_velocity_kmh = parseFloat(customVelocity);
      if (customVpn) customOverrides.is_vpn = 1.0;

      const res = await runAnomalyScenario(
        targetId,
        Object.keys(customOverrides).length > 0 ? customOverrides : undefined
      );
      setScenarioResult(res);
    } catch (e) {
      setError(apiErrorMessage(e, "Scenario execution failed."));
    } finally {
      setBusy("");
    }
  }

  async function narrate() {
    if (!selectedAlert) return;
    setBusy("narrate");
    setError("");
    try {
      const output = await generateIncidentNarrative({
        user_id: selectedAlert.user_id ?? "unknown",
        username: selectedAlert.username ?? "system",
        risk_score: selectedAlert.trust_score ?? 25,
        risk_level:
          selectedAlert.severity === "CRITICAL" ? "CRITICAL" : selectedAlert.severity,
        action:
          selectedAlert.severity === "CRITICAL" ? "REVOKE_SESSION" : "STEP_UP_MFA",
        overrides: [selectedAlert.category],
        factors: [],
        threat_details: selectedAlert.evidence,
      });
      setNarrative(output.narrative);
      setModel(output.model);
    } catch (e) {
      setError(apiErrorMessage(e, "Narrative generation failed."));
    } finally {
      setBusy("");
    }
  }

  async function buildBaseline() {
    setBusy("baseline");
    setError("");
    try {
      setBaseline(await synthesizeBaseline("employee", "Engineering", ["resources:read"]));
    } catch (e) {
      setError(apiErrorMessage(e, "Baseline synthesis failed."));
    } finally {
      setBusy("");
    }
  }

  const selectedScenario =
    scenarios.find((s) => s.id === selectedScenarioId) || scenarios[0];

  return (
    <Page
      title="AI intelligence & Anomaly Lab"
      description="Real Isolation Forest ML inference (.pkl), SHAP feature attribution, zero trust policy decisions, and tamper-evident audit verification."
      eyebrow="AI-Powered Zero Trust"
    >
      {error && (
        <div className="ops-error" role="alert">
          {error}
        </div>
      )}

      <div className="ops-tabs" role="tablist" aria-label="AI Intelligence sections">
        {TABS.map((name) => (
          <button
            key={name}
            role="tab"
            aria-selected={tab === name}
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </div>

      {/* ── TAB 1: SINGLE ANOMALY SCENARIO RUNNER ── */}
      {tab === "Anomaly scenario runner" && (
        <div className="grid gap-6 xl:grid-cols-[440px_1fr]">
          {/* Left Column: Predefined Scenario Selector */}
          <div className="flex flex-col gap-4">
            <Card title="1. Select Synthetic Scenario">
              <div className="flex flex-col gap-2.5">
                {scenarios.map((s) => {
                  const isSel = s.id === selectedScenarioId;
                  return (
                    <div
                      key={s.id}
                      onClick={() => {
                        setSelectedScenarioId(s.id);
                        setCustomRpm("");
                        setCustomVelocity("");
                        setCustomVpn(false);
                      }}
                      className={`cursor-pointer rounded-lg border p-3 transition-all ${
                        isSel
                          ? "border-primary-500 bg-primary-50/40 shadow-sm dark:bg-primary-950/20"
                          : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-900"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <strong className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                          {s.name}
                        </strong>
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                            s.category === "baseline"
                              ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300"
                              : "bg-rose-100 text-rose-800 dark:bg-rose-950/50 dark:text-rose-300"
                          }`}
                        >
                          {s.category}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                        {s.description}
                      </p>
                      <div className="mt-2 flex items-center justify-between border-t border-slate-100 pt-1.5 text-[11px] text-slate-500 dark:border-slate-800">
                        <span>
                          Expected score: <strong>{s.expected_anomaly_score_range}</strong>
                        </span>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">
                          Action: {s.expected_action}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Optional Custom Overrides */}
              {selectedScenario && (
                <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-900/60">
                  <span className="block text-xs font-bold uppercase tracking-wider text-slate-500">
                    Synthetic Overrides (Optional)
                  </span>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <label className="text-[11px] text-slate-600 dark:text-slate-400">
                        Requests/min
                      </label>
                      <input
                        type="number"
                        placeholder={String(selectedScenario.features.requests_per_minute)}
                        value={customRpm}
                        onChange={(e) => setCustomRpm(e.target.value)}
                        className="mt-0.5 w-full rounded border border-slate-300 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-950"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-600 dark:text-slate-400">
                        Travel Speed (km/h)
                      </label>
                      <input
                        type="number"
                        placeholder={String(selectedScenario.features.travel_velocity_kmh)}
                        value={customVelocity}
                        onChange={(e) => setCustomVelocity(e.target.value)}
                        className="mt-0.5 w-full rounded border border-slate-300 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-950"
                      />
                    </div>
                  </div>
                  <label className="mt-2.5 flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300">
                    <input
                      type="checkbox"
                      checked={customVpn}
                      onChange={(e) => setCustomVpn(e.target.checked)}
                      className="rounded border-slate-300"
                    />
                    <span>Force VPN / Proxy flag on</span>
                  </label>
                </div>
              )}

              <button
                className="ops-button mt-4 w-full py-2.5 text-center text-xs font-bold tracking-wide"
                disabled={busy === "scenario"}
                onClick={() => void handleRunScenario()}
              >
                {busy === "scenario"
                  ? "⚡ Running Inference & Audit Verification…"
                  : "⚡ Run Real Inference & Verify Pipeline"}
              </button>
            </Card>
          </div>

          {/* Right Column: Execution Results & Verification Gates */}
          <div className="flex flex-col gap-4">
            {!scenarioResult ? (
              <Card title="2. Scenario Execution & Verification Results">
                <Empty>
                  Select a synthetic scenario on the left and click{" "}
                  <strong>Run Real Inference & Verify Pipeline</strong> to inspect ML scores,
                  SHAP feature attribution, and tamper-evident audit logs.
                </Empty>
              </Card>
            ) : (
              <>
                {/* Overall Scorecard Banner */}
                <div
                  className={`flex items-center justify-between rounded-xl border p-4 shadow-sm ${
                    scenarioResult.overall_result === "PASS"
                      ? "border-emerald-500 bg-emerald-50/60 dark:border-emerald-800/80 dark:bg-emerald-950/20"
                      : "border-rose-500 bg-rose-50/60 dark:border-rose-800/80 dark:bg-rose-950/20"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`flex h-10 w-10 items-center justify-center rounded-full text-lg font-black ${
                        scenarioResult.overall_result === "PASS"
                          ? "bg-emerald-500 text-white"
                          : "bg-rose-500 text-white"
                      }`}
                    >
                      {scenarioResult.overall_result === "PASS" ? "✓" : "✗"}
                    </span>
                    <div>
                      <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                        Verification Status: {scenarioResult.overall_result}
                      </h3>
                      <p className="text-xs text-slate-600 dark:text-slate-400">
                        Scenario: <strong>{scenarioResult.scenario.name}</strong> · Total
                        latency: <strong>{scenarioResult.total_latency_ms}ms</strong>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <RiskChip
                      level={scenarioResult.policy_decision.risk_level}
                      score={scenarioResult.policy_decision.trust_score}
                    />
                    <span className="rounded-lg bg-slate-900 px-3 py-1.5 font-mono text-xs font-bold text-white dark:bg-slate-100 dark:text-slate-900">
                      {scenarioResult.policy_decision.action}
                    </span>
                  </div>
                </div>

                {/* 4-Gate Verification Matrix */}
                <Card title="4-Gate Verification Matrix">
                  <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                    {Object.entries(scenarioResult.verification_gates).map(([key, gate]) => (
                      <div
                        key={key}
                        className={`rounded-lg border p-3 ${
                          gate.passed
                            ? "border-emerald-200 bg-emerald-50/40 dark:border-emerald-900/50 dark:bg-emerald-950/10"
                            : "border-rose-200 bg-rose-50/40 dark:border-rose-900/50 dark:bg-rose-950/10"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                            {gate.gate_name}
                          </span>
                          <span
                            className={`rounded px-1 text-[10px] font-black ${
                              gate.passed
                                ? "bg-emerald-200 text-emerald-900 dark:bg-emerald-900 dark:text-emerald-100"
                                : "bg-rose-200 text-rose-900 dark:bg-rose-900 dark:text-rose-100"
                            }`}
                          >
                            {gate.status}
                          </span>
                        </div>
                        <p className="mt-1.5 text-xs text-slate-700 dark:text-slate-300">
                          {gate.details}
                        </p>
                      </div>
                    ))}
                  </div>
                </Card>

                {/* Inference & SHAP Attribution Side-by-Side */}
                <div className="grid gap-4 md:grid-cols-2">
                  {/* Real ML Model Inference */}
                  <Card title="Real Model Inference (.pkl)">
                    <div className="flex flex-col gap-2.5 text-xs">
                      <div className="flex items-center justify-between border-b border-slate-100 pb-2 dark:border-slate-800">
                        <span className="text-slate-500">Anomaly Score</span>
                        <strong className="font-mono text-base text-slate-900 dark:text-slate-100">
                          {scenarioResult.inference.anomaly_score.toFixed(4)}{" "}
                          <span className="text-xs font-normal text-slate-500">(0.0 - 1.0)</span>
                        </strong>
                      </div>
                      <div className="flex items-center justify-between border-b border-slate-100 pb-2 dark:border-slate-800">
                        <span className="text-slate-500">Model File</span>
                        <code className="font-mono text-xs text-primary-600 dark:text-primary-400">
                          {scenarioResult.inference.model_name}
                        </code>
                      </div>
                      <div className="flex items-center justify-between border-b border-slate-100 pb-2 dark:border-slate-800">
                        <span className="text-slate-500">Inference Duration</span>
                        <span className="font-mono font-semibold text-slate-700 dark:text-slate-300">
                          {scenarioResult.inference.duration_ms} ms
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500">Calculated Trust Score</span>
                        <strong className="text-sm text-slate-900 dark:text-slate-100">
                          {scenarioResult.policy_decision.trust_score.toFixed(1)} / 100
                        </strong>
                      </div>
                    </div>
                  </Card>

                  {/* SHAP Feature-Level Attribution */}
                  <Card title="SHAP Feature Attributions">
                    <div className="flex flex-col gap-2">
                      <div className="text-[11px] text-slate-500">
                        Method: <strong>{scenarioResult.shap_explanation.method}</strong> · Top
                        anomaly drivers:
                      </div>
                      <div className="flex flex-col gap-1.5">
                        {scenarioResult.shap_explanation.top_anomaly_drivers
                          .slice(0, 4)
                          .map((d) => (
                            <div
                              key={d.feature}
                              className="rounded border border-rose-100 bg-rose-50/50 p-2 text-xs dark:border-rose-900/30 dark:bg-rose-950/20"
                            >
                              <div className="flex items-center justify-between">
                                <strong className="font-mono text-rose-700 dark:text-rose-400">
                                  {d.feature}
                                </strong>
                                <span className="font-mono font-bold text-rose-600 dark:text-rose-300">
                                  {d.impact_percent}
                                </span>
                              </div>
                              <p className="mt-0.5 text-[11px] text-slate-600 dark:text-slate-400">
                                {d.description} (Value: {d.raw_value})
                              </p>
                            </div>
                          ))}
                      </div>
                    </div>
                  </Card>
                </div>

                {/* Audit Hash Chain Cryptographic Verification */}
                <Card title="Cryptographic Audit Verification (SHA-256 Seal)">
                  <div className="rounded-lg border border-slate-200 bg-slate-950 p-3.5 font-mono text-xs text-slate-200">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-[11px] text-emerald-400">
                      <span>
                        ✓ Verified Tamper-Evident Hash Chain Record #
                        {scenarioResult.audit_verification.seq}
                      </span>
                      <span>Algorithm: {scenarioResult.audit_verification.verification_algorithm}</span>
                    </div>
                    <div className="mt-2.5 flex flex-col gap-1 text-[11px]">
                      <div>
                        <span className="text-slate-500">Record Hash: </span>
                        <span className="text-emerald-300">
                          {scenarioResult.audit_verification.record_hash}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Prev Hash:   </span>
                        <span className="text-slate-400">
                          {scenarioResult.audit_verification.prev_hash}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Payload Hash:</span>
                        <span className="text-slate-400">
                          {scenarioResult.audit_verification.payload_hash}
                        </span>
                      </div>
                    </div>
                  </div>
                </Card>
              </>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 2: INCIDENT INVESTIGATION ── */}
      {tab === "Incident investigation" && (
        <div className="intelligence-layout">
          <section className="incident-rail">
            <header>
              <span>Incident queue</span>
              <strong>{alerts.length}</strong>
            </header>
            {alerts.length === 0 ? (
              <Empty>No alerts available.</Empty>
            ) : (
              alerts.map((alert) => (
                <button
                  key={alert.id}
                  className={selectedAlert?.id === alert.id ? "active" : ""}
                  onClick={() => {
                    setSelectedAlert(alert);
                    setNarrative("");
                  }}
                >
                  <span className={`ops-severity ${alert.severity.toLowerCase()}`}>
                    {alert.severity}
                  </span>
                  <strong>{alert.title}</strong>
                  <small>
                    {alert.username ?? "system"} · {new Date(alert.created_at).toLocaleString()}
                  </small>
                </button>
              ))
            )}
          </section>

          <div className="intelligence-main">
            <Card
              title="Incident investigation"
              actions={
                selectedAlert && (
                  <RiskChip
                    level={selectedAlert.severity}
                    score={selectedAlert.trust_score ?? undefined}
                  />
                )
              }
            >
              {!selectedAlert ? (
                <Empty>Select an incident.</Empty>
              ) : (
                <div className="incident-detail">
                  <div className="incident-meta">
                    <div>
                      <span>Category</span>
                      <strong>{selectedAlert.category}</strong>
                    </div>
                    <div>
                      <span>Subject</span>
                      <strong>{selectedAlert.username ?? "system"}</strong>
                    </div>
                    <div>
                      <span>Status</span>
                      <strong>{selectedAlert.status}</strong>
                    </div>
                  </div>
                  <h2>{selectedAlert.title}</h2>
                  <p>{selectedAlert.description}</p>
                  <pre>{JSON.stringify(selectedAlert.evidence, null, 2)}</pre>
                  <button
                    className="ops-button"
                    disabled={busy === "narrate"}
                    onClick={narrate}
                  >
                    {busy === "narrate" ? "Analyzing…" : "Generate investigation"}
                  </button>
                </div>
              )}
            </Card>

            <section className="narrative-sheet">
              <header>
                <span>Investigation report</span>
                {model && <code>{model}</code>}
              </header>
              {narrative ? (
                <p>{narrative}</p>
              ) : (
                <div className="narrative-empty">
                  Select an alert and generate a plain-language investigation report.
                </div>
              )}
            </section>
          </div>
        </div>
      )}

      {/* ── TAB 3: BEHAVIORAL BASELINE SYNTHESIS ── */}
      {tab === "Behavioral baseline synthesis" && (
        <div className="flex flex-col gap-4">
          <Card
            title="Behavioral baseline synthesis"
            actions={
              <button
                className="ops-button"
                disabled={busy === "baseline"}
                onClick={buildBaseline}
              >
                {busy === "baseline" ? "Synthesizing…" : "Generate baseline"}
              </button>
            }
          >
            {!baseline ? (
              <p className="text-sm text-slate-600">
                Generate a role-aware employee baseline using the configured LLM or
                deterministic fallback.
              </p>
            ) : (
              <pre className="ops-json">{JSON.stringify(baseline, null, 2)}</pre>
            )}
          </Card>
        </div>
      )}
    </Page>
  );
}
