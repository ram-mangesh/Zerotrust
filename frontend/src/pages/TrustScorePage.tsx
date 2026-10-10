import { useEffect, useState } from "react";
import { getTrustConfig, updateTrustConfig, evaluateMyTrust } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import Page, { Card } from "../components/layout/Page";
import TrustPanel from "../components/TrustPanel";

const FACTOR_INFO: Record<string, { label: string; desc: string }> = {
  identity: { label: "Identity & Credential", desc: "Password strength, MFA outcome, credential age, lockout streak" },
  device: { label: "Device Posture", desc: "Approved hardware key, WebCrypto binding, OS/browser consistency" },
  network: { label: "Network Context", desc: "IP reputation score, Tor/VPN exit node, datacenter ASN, mid-session drift" },
  behavior: { label: "Behavior Dynamics", desc: "Isolation Forest ML anomaly, request velocity, keystroke WPM & pointer speed" },
  location: { label: "Geographic Location", desc: "Distance from usual baseline, new country entry, impossible travel velocity" },
  temporal: { label: "Temporal Circadian", desc: "Hour deviation from usual window, weekend access, session duration outlier" },
};

export default function TrustScorePage() {
  const { me } = useAuth();
  const isOperator = me?.is_admin || me?.role === "security_analyst";

  const [weights, setWeights] = useState<Record<string, number>>({
    identity: 25, device: 20, network: 20, behavior: 20, location: 10, temporal: 5,
  });
  const [bands, setBands] = useState<Record<string, number>>({
    LOW: 80, MEDIUM: 60, HIGH: 40,
  });

  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getTrustConfig().then((cfg) => {
      if (cfg.weights) setWeights(cfg.weights);
      if (cfg.bands) {
        const bMap: Record<string, number> = {};
        for (const b of cfg.bands) {
          bMap[b.level] = b.min;
        }
        setBands((prev) => ({ ...prev, ...bMap }));
      }
    }).catch(() => null);
  }, []);

  const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);

  function setWeight(key: string, val: number) {
    setWeights((prev) => ({ ...prev, [key]: Math.max(0, Math.min(100, val)) }));
  }

  function setBand(key: string, val: number) {
    setBands((prev) => ({ ...prev, [key]: Math.max(0, Math.min(100, val)) }));
  }

  function applyPreset(presetWeights: Record<string, number>) {
    setWeights(presetWeights);
  }

  async function handleSaveConfig() {
    setSaving(true);
    setMessage(null);
    setError(null);

    if (totalWeight !== 100) {
      setError(`Weights must sum to exactly 100% (currently ${totalWeight}%).`);
      setSaving(false);
      return;
    }

    try {
      await updateTrustConfig({ weights, bands });
      setMessage("Zero Trust Engine weights and risk thresholds updated live!");
      await evaluateMyTrust().catch(() => null);
      setTimeout(() => setMessage(null), 4000);
    } catch {
      setError("Failed to save configuration. You need 'policies:write' permissions.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Page
      title="Trust scoring"
      description="Live behavioral trust engine configuration: tune 6-factor weights, risk band boundaries, and observe instant effects."
      eyebrow="Access controls"
    >
      {/* ── Standardized Convention Banner ── */}
      <div className="mb-6 rounded-xl border border-blue-200 bg-blue-50/70 p-4 text-slate-800">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="text-xl">📐</span>
            <div>
              <div className="text-sm font-semibold text-blue-950">Universal Score Convention</div>
              <div className="text-xs text-slate-600">
                <strong>Trust Score (0–100):</strong> Higher is more trusted (100 = Optimal Safety). &nbsp;|&nbsp;
                <strong className="text-amber-800">Risk Score = 100 − Trust:</strong> Lower is safer (0 = Zero Risk).
              </div>
            </div>
          </div>
          <div className="rounded-lg border border-blue-200 bg-white px-3 py-1 font-mono text-xs font-semibold text-blue-800 shadow-xs">
            Formula: Risk = 100 − Trust
          </div>
        </div>
      </div>

      {isOperator && (
        <div className="mb-6 grid gap-6 lg:grid-cols-2">
          {/* ── Factor Weights Card ── */}
          <Card
            title="6-Factor weight distribution"
            actions={
              <span
                className={`font-mono text-xs font-bold px-2.5 py-1 rounded-full border ${
                  totalWeight === 100
                    ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                    : "bg-red-50 text-red-800 border-red-200"
                }`}
              >
                Total: {totalWeight}%
              </span>
            }
          >
            {/* Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-500">Presets:</span>
              <button
                type="button"
                onClick={() => applyPreset({ identity: 25, device: 20, network: 20, behavior: 20, location: 10, temporal: 5 })}
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-slate-700 hover:bg-slate-50 transition"
              >
                Standard Balanced
              </button>
              <button
                type="button"
                onClick={() => applyPreset({ identity: 30, device: 30, network: 15, behavior: 15, location: 5, temporal: 5 })}
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-slate-700 hover:bg-slate-50 transition"
              >
                Device & Hardware Strict
              </button>
              <button
                type="button"
                onClick={() => applyPreset({ identity: 20, device: 15, network: 20, behavior: 35, location: 5, temporal: 5 })}
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-slate-700 hover:bg-slate-50 transition"
              >
                Behavior / Anomaly Heavy
              </button>
            </div>

            {/* Sliders */}
            <div className="mt-4 space-y-3">
              {Object.entries(weights).map(([factor, weight]) => {
                const info = FACTOR_INFO[factor] || { label: factor, desc: "" };
                return (
                  <div key={factor} className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-900">{info.label}</span>
                      <div className="flex items-center gap-1.5">
                        <input
                          type="number"
                          min="0"
                          max="100"
                          value={weight}
                          onChange={(e) => setWeight(factor, parseInt(e.target.value) || 0)}
                          className="w-14 rounded-md border border-slate-300 bg-white px-2 py-0.5 text-right font-mono text-xs text-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900"
                        />
                        <span className="text-slate-500 font-medium">%</span>
                      </div>
                    </div>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={weight}
                      onChange={(e) => setWeight(factor, parseInt(e.target.value) || 0)}
                      className="mt-2 w-full accent-shell"
                    />
                    <div className="mt-1 text-[11px] text-slate-500">{info.desc}</div>
                  </div>
                );
              })}
            </div>
          </Card>

          {/* ── Risk Band Thresholds Card ── */}
          <Card title="Risk bands & action boundaries">
            <p className="text-xs text-slate-500 mb-4">
              Minimum Trust Score required for each operational enforcement mode:
            </p>

            <div className="space-y-3.5 text-xs">
              {/* LOW BAND */}
              <div className="rounded-lg border border-emerald-200 bg-emerald-50/70 p-3.5">
                <div className="flex items-center justify-between font-semibold text-emerald-900">
                  <span>🟢 LOW RISK (Action: ALLOW)</span>
                  <span className="font-mono">Min Trust: {bands.LOW}</span>
                </div>
                <input
                  type="range"
                  min="50"
                  max="95"
                  value={bands.LOW}
                  onChange={(e) => setBand("LOW", parseInt(e.target.value))}
                  className="mt-2.5 w-full accent-emerald-600"
                />
                <div className="mt-1 text-[11px] text-emerald-800/80">Full Access (Read/Write) granted to all authorized resources.</div>
              </div>

              {/* MEDIUM BAND */}
              <div className="rounded-lg border border-amber-200 bg-amber-50/70 p-3.5">
                <div className="flex items-center justify-between font-semibold text-amber-900">
                  <span>🟡 MEDIUM RISK (Action: ALLOW_LIMITED)</span>
                  <span className="font-mono">Min Trust: {bands.MEDIUM}</span>
                </div>
                <input
                  type="range"
                  min="40"
                  max="80"
                  value={bands.MEDIUM}
                  onChange={(e) => setBand("MEDIUM", parseInt(e.target.value))}
                  className="mt-2.5 w-full accent-amber-600"
                />
                <div className="mt-1 text-[11px] text-amber-800/80">Restricted Read-Only mode (mutations and file updates blocked).</div>
              </div>

              {/* HIGH BAND */}
              <div className="rounded-lg border border-orange-200 bg-orange-50/70 p-3.5">
                <div className="flex items-center justify-between font-semibold text-orange-900">
                  <span>🟠 HIGH RISK (Action: STEP_UP_MFA)</span>
                  <span className="font-mono">Min Trust: {bands.HIGH}</span>
                </div>
                <input
                  type="range"
                  min="20"
                  max="60"
                  value={bands.HIGH}
                  onChange={(e) => setBand("HIGH", parseInt(e.target.value))}
                  className="mt-2.5 w-full accent-orange-600"
                />
                <div className="mt-1 text-[11px] text-orange-800/80">MFA Challenge re-verification required to proceed.</div>
              </div>

              {/* CRITICAL BAND */}
              <div className="rounded-lg border border-red-200 bg-red-50/70 p-3.5 text-red-900">
                <div className="font-semibold text-red-900">🔴 CRITICAL RISK (Action: BLOCK / REVOKE)</div>
                <div className="mt-1 text-[11px] text-red-800/80">Trust scores below {bands.HIGH} trigger immediate session termination & edge blockage.</div>
              </div>
            </div>

            {/* Save Button */}
            <div className="mt-5 border-t border-slate-100 pt-4">
              {message && <div className="mb-3 rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs font-semibold text-emerald-800">{message}</div>}
              {error && <div className="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs font-semibold text-red-800">{error}</div>}
              <button
                type="button"
                onClick={handleSaveConfig}
                disabled={saving}
                className="w-full rounded-lg bg-shell px-4 py-2.5 text-sm font-medium text-white shadow-sm hover:opacity-90 disabled:opacity-50 transition"
              >
                {saving ? "Updating Zero Trust Engine…" : "Save & Apply Live to Zero Trust Engine"}
              </button>
            </div>
          </Card>
        </div>
      )}

      {/* ── Active Session Factor Breakdown & Evidence ── */}
      <TrustPanel />
    </Page>
  );
}
