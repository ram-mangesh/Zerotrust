import { Fragment, useCallback, useEffect, useState } from "react";
import {
  auditExportUrl, getAudit, tokenStore, verifyChain,
  type AuditRecord, type ChainVerification,
} from "../api/client";
import { explainAnomaly, type SHAPExplanationResult } from "../api/operations";
import Page, { Card, Empty } from "../components/layout/Page";

function extractFeaturesFromPayload(payload: Record<string, any> | undefined): Record<string, number> {
  const p = payload || {};
  const now = new Date();
  const hour = now.getUTCHours();
  const rad = (hour * Math.PI) / 12.0;

  const distance = p.distance_from_usual_km ?? (p.evidence?.distance_km ?? 0.0);
  const velocity = p.travel_velocity_kmh ?? (p.evidence?.velocity_kmh ?? 0.0);
  const is_new_country = p.is_new_country ? 1.0 : (p.country && p.country !== "IN" ? 1.0 : 0.0);
  const is_known_device = p.is_known_device !== undefined ? (p.is_known_device ? 1.0 : 0.0) : 1.0;
  const is_vpn = p.is_vpn ? 1.0 : 0.0;
  const ip_rep = p.ip_reputation ?? (p.threat_score ?? 0.0);
  const rpm = p.requests_per_minute ?? (p.action === "ACCESS_DENIED" ? 12.0 : 2.0);
  const distinct_res = p.distinct_resources ?? (p.action === "ACCESS_DENIED" ? 5.0 : 1.0);
  const duration = p.session_duration_min ?? 45.0;
  const failed_auth = p.failed_auth_count_24h ?? (p.action === "LOGIN_FAILED" ? 3.0 : 0.0);

  return {
    hour_sin: Math.sin(rad),
    hour_cos: Math.cos(rad),
    day_of_week: now.getUTCDay(),
    is_known_device: is_known_device,
    geo_distance_from_usual_km: Number(distance),
    is_new_country: is_new_country,
    ip_reputation_score: Number(ip_rep),
    is_vpn: is_vpn,
    requests_per_minute: Number(rpm),
    session_duration_min: Number(duration),
    num_distinct_resources: Number(distinct_res),
    failed_auth_count_24h: Number(failed_auth),
    travel_velocity_kmh: Number(velocity),
  };
}

export default function AuditPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [action, setAction] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [check, setCheck] = useState<ChainVerification | null>(null);
  const [checking, setChecking] = useState(false);

  // SHAP Modal State
  const [shapModalRecord, setShapModalRecord] = useState<AuditRecord | null>(null);
  const [shapResult, setShapResult] = useState<SHAPExplanationResult | null>(null);
  const [shapLoading, setShapLoading] = useState(false);
  const [shapError, setShapError] = useState<string | null>(null);

  const limit = 50;

  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (query) params.set("q", query);
    if (action) params.set("action", action);
    params.set("limit", String(limit));
    params.set("offset", String(offset));
    getAudit(`?${params}`)
      .then((d) => {
        setRecords(d.records || []);
        setTotal(d.total || 0);
      })
      .catch(() => {
        setRecords([]);
        setTotal(0);
      });
  }, [query, action, offset]);

  useEffect(load, [load]);

  async function runVerify() {
    setChecking(true);
    try {
      setCheck(await verifyChain());
    } finally {
      setChecking(false);
    }
  }

  async function openShapModal(record: AuditRecord) {
    setShapModalRecord(record);
    setShapResult(null);
    setShapLoading(true);
    setShapError(null);

    const features = extractFeaturesFromPayload(record.payload);
    try {
      const res = await explainAnomaly(features, record.actor_id || undefined);
      setShapResult(res);
    } catch (e: any) {
      setShapError(e?.response?.data?.detail || "Could not calculate SHAP explanation for this record.");
    } finally {
      setShapLoading(false);
    }
  }

  async function exportCsv() {
    const params = new URLSearchParams();
    if (query) params.set("q", query);
    if (action) params.set("action", action);
    const response = await fetch(`${auditExportUrl}?${params}`, {
      headers: { Authorization: `Bearer ${tokenStore.access ?? ""}` },
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "ztna-audit.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  const drivers = (shapResult as any)?.top_anomaly_drivers || [];
  const mitigators = (shapResult as any)?.top_mitigating_signals || (shapResult as any)?.top_mitigating_factors || [];

  return (
    <Page
      title="Audit Trail & Cryptographic Ledger"
      description="Every security event, hash-linked to the one before it with 1-click SHAP ML anomaly feature-level explainability."
      eyebrow="Immutable Compliance Vault"
      actions={
        <>
          <button
            onClick={exportCsv}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 hover:bg-slate-700"
          >
            Export CSV
          </button>
          <button
            onClick={runVerify}
            disabled={checking}
            className="rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {checking ? "Verifying…" : "Verify SHA-256 Chain"}
          </button>
        </>
      }
    >
      {/* ── Convention Banner ── */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-blue-900/40 bg-blue-950/20 px-4 py-2.5 text-xs text-slate-300">
        <div className="flex items-center gap-2">
          <span>📐</span>
          <span>
            <strong>Scoring Convention:</strong> Trust Score (0–100, Higher is Better) &nbsp;⟷&nbsp; 
            <strong className="text-amber-400">Risk Score = 100 − Trust</strong> (Lower is Safer).
          </span>
        </div>
        <span className="font-mono text-blue-400">1-Click SHAP XAI Available per Row</span>
      </div>

      {check && (
        <div
          className={`mb-4 rounded-lg border px-4 py-3 text-sm ${
            check.valid
              ? "border-emerald-800 bg-emerald-950/30 text-emerald-300"
              : "border-red-800 bg-red-950/30 text-red-300"
          }`}
        >
          <div className="font-semibold">
            {check.valid ? "✅ Cryptographic Chain Verified (Tamper-Evident)" : "🚨 Chain BROKEN / Tampering Detected"}
          </div>
          <p className="mt-1 text-xs">
            {check.records_checked.toLocaleString()} records verified in {check.duration_ms.toFixed(0)} ms
            {check.valid ? ", unbroken from genesis." : ` — first break at position ${check.broken_at}: ${check.reason}.`}
          </p>
          <p className="mt-1 break-all font-mono text-[11px] opacity-70">
            Head Hash: {check.head_hash}
          </p>
        </div>
      )}

      <div className="mb-4 flex flex-wrap gap-2">
        <input
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setOffset(0);
          }}
          placeholder="Search action, actor, resource…"
          className="min-w-64 flex-1 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-2 text-sm text-slate-200 outline-none focus:border-blue-500"
        />
        <select
          value={action}
          onChange={(e) => {
            setAction(e.target.value);
            setOffset(0);
          }}
          className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-200"
          aria-label="Action"
        >
          <option value="">All actions</option>
          {[
            "LOGIN_SUCCESS", "LOGIN_FAILED", "PASSWORD_ACCEPTED", "MFA_FAILED",
            "SESSION_REVOKED", "SESSION_CONTEXT_MISMATCH", "TRUST_EVALUATED",
            "ACCESS_GRANTED", "ACCESS_DENIED", "ALERT_RAISED", "ACCOUNT_LOCKED",
            "DEVICE_APPROVED", "POLICY_CREATED", "USER_UPDATED", "TRUST_CONFIG_UPDATED",
          ].map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </div>

      <Card>
        {!records || records.length === 0 ? (
          <Empty>No records match.</Empty>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-800 text-sm">
                <thead className="text-left text-xs uppercase tracking-wide text-slate-400">
                  <tr>
                    <th className="px-3 py-2.5 font-medium">#</th>
                    <th className="px-3 py-2.5 font-medium">When</th>
                    <th className="px-3 py-2.5 font-medium">Actor</th>
                    <th className="px-3 py-2.5 font-medium">Action</th>
                    <th className="px-3 py-2.5 font-medium">Resource</th>
                    <th className="px-3 py-2.5 font-medium">SHAP XAI</th>
                    <th className="px-3 py-2.5 font-medium">Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {records.map((r) => (
                    <Fragment key={r.seq}>
                      <tr className="hover:bg-slate-800/40">
                        <td className="px-3 py-2 font-mono text-xs tabular-nums text-slate-400">
                          <button
                            type="button"
                            className="audit-row-toggle text-blue-400 hover:underline"
                            aria-expanded={expanded === r.seq}
                            onClick={() => setExpanded(expanded === r.seq ? null : r.seq)}
                          >
                            {r.seq}
                          </button>
                        </td>
                        <td className="px-3 py-2 text-xs text-slate-300">
                          {new Date(r.timestamp).toLocaleString()}
                        </td>
                        <td className="px-3 py-2 font-medium text-slate-200">
                          {r.actor_label}
                        </td>
                        <td className="px-3 py-2">
                          <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] text-blue-300 border border-slate-700">
                            {r.action}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-xs text-slate-400">
                          {r.resource_type}
                          {r.resource_id && ` ${r.resource_id.slice(0, 12)}`}
                        </td>
                        <td className="px-3 py-2">
                          <button
                            type="button"
                            onClick={() => openShapModal(r)}
                            className="rounded border border-purple-800/60 bg-purple-950/40 px-2 py-0.5 font-mono text-[11px] text-purple-300 hover:bg-purple-900/60 hover:text-purple-200 transition"
                          >
                            ✦ Explain SHAP
                          </button>
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-slate-500">
                          {r.record_hash ? `${r.record_hash.slice(0, 12)}…` : "—"}
                        </td>
                      </tr>
                      {expanded === r.seq && (
                        <tr className="bg-slate-900/80">
                          <td colSpan={7} className="px-4 py-3">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-xs font-semibold text-slate-300">Payload Evidence:</span>
                              <button
                                type="button"
                                onClick={() => openShapModal(r)}
                                className="rounded bg-purple-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-purple-500"
                              >
                                View SHAP Attribution Analysis ➔
                              </button>
                            </div>
                            <pre className="overflow-x-auto text-[11px] leading-relaxed text-emerald-400 bg-slate-950 p-3 rounded-lg border border-slate-800">
                              {JSON.stringify(r.payload, null, 2)}
                            </pre>
                            <div className="mt-2 flex flex-wrap gap-4 font-mono text-[11px] text-slate-500">
                              <div>prev: {r.prev_hash ? `${r.prev_hash.slice(0, 16)}…` : "genesis"}</div>
                              <div>payload: {r.payload_hash ? `${r.payload_hash.slice(0, 16)}…` : "—"}</div>
                              <div>record: {r.record_hash ? `${r.record_hash.slice(0, 16)}…` : "—"}</div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-4 flex items-center justify-between text-sm text-slate-400">
              <span>
                {offset + 1}–{Math.min(offset + limit, total)} of {total.toLocaleString()}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                  className="rounded border border-slate-800 bg-slate-900 px-3 py-1 disabled:opacity-40"
                >
                  Previous
                </button>
                <button
                  onClick={() => setOffset(offset + limit)}
                  disabled={offset + limit >= total}
                  className="rounded border border-slate-800 bg-slate-900 px-3 py-1 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </Card>

      {/* ── Direct SHAP Feature Attribution Modal ── */}
      {shapModalRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6 text-slate-200 shadow-2xl">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xl">✦</span>
                  <h3 className="text-base font-bold text-white">
                    SHAP Feature-Level Anomaly Explanation
                  </h3>
                </div>
                <div className="mt-1 text-xs text-slate-400">
                  Audit Record #{shapModalRecord.seq} · Action: <span className="font-mono text-blue-400">{shapModalRecord.action}</span> · Actor: <strong>{shapModalRecord.actor_label}</strong>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShapModalRecord(null)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-700"
              >
                ✕ Close
              </button>
            </div>

            {shapLoading && (
              <div className="py-12 text-center text-sm text-slate-400">
                <span className="inline-block animate-spin mr-2">⚙️</span>
                Decomposing 13-D Isolation Forest features via SHAP TreeExplainer…
              </div>
            )}

            {shapError && (
              <div className="my-6 rounded-lg border border-red-900/50 bg-red-950/20 p-4 text-xs text-red-300">
                ⚠️ {shapError}
              </div>
            )}

            {shapResult && (
              <div className="mt-4 space-y-5">
                {/* Anomaly Gauge & Method */}
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <div>
                    <div className="text-xs text-slate-400">Isolation Forest Anomaly Score</div>
                    <div className="text-2xl font-black text-amber-400 font-mono">
                      {(shapResult.anomaly_score * 100).toFixed(1)} / 100
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-slate-400">Attribution Method</div>
                    <span className="rounded bg-blue-950 border border-blue-800 px-2 py-0.5 font-mono text-[11px] text-blue-300">
                      {shapResult.method}
                    </span>
                  </div>
                </div>

                {/* Top Anomaly Drivers */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-red-400 mb-2">
                    🚨 Top Anomaly Drivers (Pushed Risk Higher)
                  </h4>
                  {drivers.length === 0 ? (
                    <div className="text-xs text-slate-500">No significant risk drivers identified.</div>
                  ) : (
                    <div className="space-y-2">
                      {drivers.map((d: any) => (
                        <div key={d.feature} className="rounded-lg border border-red-900/40 bg-red-950/20 p-2.5 text-xs">
                          <div className="flex justify-between font-medium">
                            <span className="text-slate-200 font-mono">{d.feature}</span>
                            <span className="text-red-400 font-bold">{d.impact_percent || d.impact_signed}</span>
                          </div>
                          <div className="mt-1 text-[11px] text-slate-400">{d.description}</div>
                          <div className="mt-1.5 h-1.5 w-full rounded-full bg-slate-800">
                            <div className="h-full rounded-full bg-red-500" style={{ width: `${Math.min(100, Math.abs(d.impact_signed || 0.2) * 200)}%` }} />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Top Mitigating Factors */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2">
                    🛡️ Mitigating Trust Factors (Kept Score Safe)
                  </h4>
                  {mitigators.length === 0 ? (
                    <div className="text-xs text-slate-500">No mitigating trust factors identified.</div>
                  ) : (
                    <div className="space-y-2">
                      {mitigators.map((m: any) => (
                        <div key={m.feature} className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-2.5 text-xs">
                          <div className="flex justify-between font-medium">
                            <span className="text-slate-200 font-mono">{m.feature}</span>
                            <span className="text-emerald-400 font-bold">{m.impact_percent || m.impact_signed}</span>
                          </div>
                          <div className="mt-1 text-[11px] text-slate-400">{m.description}</div>
                          <div className="mt-1.5 h-1.5 w-full rounded-full bg-slate-800">
                            <div className="h-full rounded-full bg-emerald-500" style={{ width: `${Math.min(100, Math.abs(m.impact_signed || 0.15) * 300)}%` }} />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </Page>
  );
}
