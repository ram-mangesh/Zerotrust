import { useCallback, useEffect, useMemo, useState } from "react";
import { apiErrorMessage } from "../api/http";
import {
  blockIP,
  getBlockedIPs,
  getEDRAgents,
  getEDREvents,
  getSimulatorScenarios,
  isolateEDRAgent,
  resetSimulator,
  restoreEDRAgent,
  runSimulatorScenario,
  unblockIP,
  type BlockedIP,
  type EDRAgent,
  type EDREvent,
  type SimulationResult,
  type SimulatorScenario,
} from "../api/operations";
import { usePermissions } from "../auth/usePermissions";
import Page, { Card, Empty, RiskChip } from "../components/layout/Page";

const TABS = ["Endpoints", "Telemetry", "Network blocks", "Attack lab"] as const;
type Tab = (typeof TABS)[number];

export default function SecurityOperationsPage() {
  const [tab, setTab] = useState<Tab>("Endpoints");
  const [agents, setAgents] = useState<EDRAgent[]>([]);
  const [events, setEvents] = useState<EDREvent[]>([]);
  const [blocks, setBlocks] = useState<BlockedIP[]>([]);
  const [scenarios, setScenarios] = useState<SimulatorScenario[]>([]);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [ip, setIP] = useState("");
  const [reason, setReason] = useState("Security operations block");
  const { can } = usePermissions();

  const load = useCallback(async () => {
    const settled = await Promise.allSettled([
      getEDRAgents(),
      getEDREvents("?limit=80"),
      getBlockedIPs(),
      getSimulatorScenarios(),
    ]);
    if (settled[0].status === "fulfilled") setAgents(settled[0].value);
    if (settled[1].status === "fulfilled") setEvents(settled[1].value);
    if (settled[2].status === "fulfilled") setBlocks(settled[2].value);
    if (settled[3].status === "fulfilled") setScenarios(settled[3].value);
  }, []);

  useEffect(() => { void load(); }, [load]);

  const stats = useMemo(() => ({
    online: agents.filter((x) => x.status === "ONLINE" && !x.is_isolated).length,
    isolated: agents.filter((x) => x.is_isolated).length,
    critical: events.filter((x) => x.severity === "CRITICAL").length,
    blocks: blocks.length,
  }), [agents, events, blocks]);

  async function contain(agent: EDRAgent) {
    setBusy(agent.agent_id); setError("");
    try {
      if (agent.is_isolated) await restoreEDRAgent(agent.agent_id);
      else await isolateEDRAgent(agent.agent_id, "Contained from security operations console");
      await load();
    } catch (e) { setError(apiErrorMessage(e, "Endpoint action failed.")); }
    finally { setBusy(""); }
  }

  async function addBlock() {
    if (!ip.trim()) return;
    setBusy("block"); setError("");
    try { await blockIP(ip.trim(), reason, 60); setIP(""); await load(); }
    catch (e) { setError(apiErrorMessage(e, "Could not block that address.")); }
    finally { setBusy(""); }
  }

  async function runScenario(id: string) {
    setBusy(id); setError(""); setResult(null);
    try { setResult(await runSimulatorScenario(id)); }
    catch (e) { setError(apiErrorMessage(e, "Simulation failed.")); }
    finally { setBusy(""); }
  }

  return (
    <Page title="Security operations" description="Endpoint containment, network enforcement, and controlled attack simulation in one operating surface." eyebrow="Response center">
      <div className="ops-stat-strip">
        <div><span>Healthy endpoints</span><strong>{stats.online}</strong></div>
        <div><span>Isolated</span><strong>{stats.isolated}</strong></div>
        <div><span>Critical events</span><strong>{stats.critical}</strong></div>
        <div><span>Blocked addresses</span><strong>{stats.blocks}</strong></div>
      </div>

      <div className="ops-tabs" role="tablist" aria-label="Security operations sections">
        {TABS.map((name) => <button key={name} role="tab" aria-selected={tab === name} onClick={() => setTab(name)}>{name}</button>)}
      </div>
      {error && <div className="ops-error" role="alert">{error}</div>}

      {tab === "Endpoints" && <Card title={`Managed endpoints (${agents.length})`}>
        {agents.length === 0 ? <Empty>No EDR agents have checked in.</Empty> : <div className="ops-table-wrap"><table><thead><tr><th>Endpoint</th><th>Agent</th><th>Status</th><th>Last heartbeat</th><th /></tr></thead><tbody>{agents.map((agent) => <tr key={agent.id}><td><strong>{agent.hostname}</strong><small>{agent.os_type} · {agent.version}</small></td><td className="font-mono text-xs">{agent.agent_id}</td><td><span className={`ops-state ${agent.is_isolated ? "danger" : "good"}`}>{agent.is_isolated ? "ISOLATED" : agent.status}</span></td><td>{new Date(agent.last_heartbeat_at).toLocaleString()}</td><td>{can("devices:revoke") && <button className={agent.is_isolated ? "ops-button" : "ops-button danger"} disabled={busy === agent.agent_id} onClick={() => contain(agent)}>{agent.is_isolated ? "Restore" : "Isolate"}</button>}</td></tr>)}</tbody></table></div>}
      </Card>}

      {tab === "Telemetry" && <Card title={`Latest endpoint telemetry (${events.length})`}>
        {events.length === 0 ? <Empty>No endpoint telemetry received.</Empty> : <div className="ops-event-list">{events.map((event) => <article key={event.id}><div><span className={`ops-severity ${event.severity.toLowerCase()}`}>{event.severity}</span><strong>{event.event_type.replaceAll("_", " ")}</strong></div><p>{event.agent_id} · {event.source} · {new Date(event.timestamp).toLocaleString()}</p><code>{JSON.stringify(event.details)}</code></article>)}</div>}
      </Card>}

      {tab === "Network blocks" && <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
        <Card title="Block an address"><div className="ops-form"><label>IP address<input value={ip} onChange={(e) => setIP(e.target.value)} placeholder="203.0.113.42" /></label><label>Reason<input value={reason} onChange={(e) => setReason(e.target.value)} /></label><button className="ops-button danger" disabled={!can("policies:write") || busy === "block"} onClick={addBlock}>Block for 60 minutes</button></div></Card>
        <Card title={`Active blocks (${blocks.length})`}>{blocks.length === 0 ? <Empty>No addresses are blocked.</Empty> : <div className="ops-block-list">{blocks.map((block) => <article key={block.id}><div><strong>{block.ip_address}</strong><span>{block.permanent ? "Permanent" : `Until ${new Date(block.blocked_until!).toLocaleString()}`}</span></div><p>{block.reason}</p>{can("policies:write") && <button onClick={async () => { await unblockIP(block.ip_address); await load(); }}>Remove</button>}</article>)}</div>}</Card>
      </div>}

      {tab === "Attack lab" && <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
        <div className="ops-scenario-grid">{scenarios.map((scenario) => <article key={scenario.id} className="ops-scenario"><div className="flex items-start justify-between gap-3"><span className="ops-category">{scenario.category.replaceAll("_", " ")}</span><span className={`ops-severity ${scenario.severity.toLowerCase()}`}>{scenario.severity}</span></div><h2>{scenario.name}</h2><p>{scenario.description}</p><dl><div><dt>Expected score</dt><dd>{scenario.expected_score_range}</dd></div><div><dt>Expected action</dt><dd>{scenario.expected_action}</dd></div></dl><button className="ops-button" disabled={Boolean(busy)} onClick={() => runScenario(scenario.id)}>{busy === scenario.id ? "Running…" : "Run scenario"}</button></article>)}</div>
        <Card title="Simulation output" actions={<button className="text-xs text-slate-600" onClick={async () => { await resetSimulator(); setResult(null); }}>Reset session</button>}>{!result ? <Empty>Run a scenario to inspect the resulting trust decision.</Empty> : <div className="ops-result"><RiskChip level={result.risk_level} score={result.final_score} /><h3>{result.action.replaceAll("_", " ")}</h3><p>{result.timeline.length} timeline stages · {result.alerts_generated.length} alerts generated</p><pre>{JSON.stringify(result.timeline, null, 2)}</pre></div>}</Card>
      </div>}
    </Page>
  );
}
