import { useEffect, useState } from "react";
import {
  getUserTrustHistory, getUsers, type TrustHistoryPoint, type UserRow,
} from "../api/client";
import TrustTrend from "../components/charts/TrustTrend";
import Page, { Card, Empty, RiskChip } from "../components/layout/Page";

export default function RiskScoresPage() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [history, setHistory] = useState<TrustHistoryPoint[]>([]);

  useEffect(() => {
    getUsers()
      .then((rows) => {
        setUsers(rows);
        if (rows.length && !selected) setSelected(rows[0].id);
      })
      .catch(() => setUsers([]));
  }, [selected]);

  useEffect(() => {
    if (!selected) return;
    getUserTrustHistory(selected).then(setHistory).catch(() => setHistory([]));
  }, [selected]);

  const notable = history.filter(
    (p) => p.risk_level !== "LOW" || p.trigger === "LOGIN",
  );

  return (
    <Page
      title="Risk scores"
      description="One account's continuous trust and computed risk over time, annotated with security triggers."
      eyebrow="Access controls"
      actions={
        <select
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 focus:outline-none focus:ring-1 focus:ring-slate-900 shadow-xs"
          aria-label="Select user"
        >
          {users.map((u) => (
            <option key={u.id} value={u.id}>
              {u.username} ({u.role})
            </option>
          ))}
        </select>
      }
    >
      {/* ── Universal Convention Banner ── */}
      <div className="mb-6 rounded-xl border border-blue-200 bg-blue-50/70 p-4 text-slate-800">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="text-xl">📐</span>
            <div>
              <div className="text-sm font-semibold text-blue-950">Unified Scoring Convention</div>
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

      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <Card title="Trust trajectory & computed risk">
          {history.length === 0 ? (
            <Empty>No score history recorded for this user.</Empty>
          ) : (
            <TrustTrend data={history.map((p) => ({ at: p.at, score: p.score, risk_level: p.risk_level }))} />
          )}
        </Card>

        <Card title="Security triggers & notable shifts">
          {notable.length === 0 ? (
            <Empty>No notable risk events for this user.</Empty>
          ) : (
            <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
              {notable.map((p, i) => {
                const computedRisk = Math.max(0, 100 - p.score);
                return (
                  <div
                    key={i}
                    className="rounded-lg border border-slate-200 bg-slate-50/70 p-3 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <RiskChip level={p.risk_level} />
                        <span className="font-mono text-emerald-700 font-bold">Trust: {p.score.toFixed(0)}</span>
                        <span className="text-slate-300 font-mono">|</span>
                        <span className="font-mono text-amber-700 font-bold">Risk: {computedRisk.toFixed(0)}</span>
                      </div>
                      <span className="text-slate-400 font-mono text-[11px]">
                        {new Date(p.at).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="mt-1.5 font-medium text-slate-800">{p.reason}</div>
                    <div className="mt-1 text-[11px] text-slate-500">
                      Trigger: <span className="font-mono text-slate-700 font-medium">{p.trigger}</span> · Action:{" "}
                      <span className="font-mono text-slate-700 font-medium">{p.action}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </Page>
  );
}
