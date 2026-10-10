import { useCallback, useEffect, useState } from "react";
import { getHealthStatus, type HealthStatus } from "../api/operations";
import Page, { Card, Empty } from "../components/layout/Page";

const ARTIFACTS = [
  ["Kubernetes", "Helm chart", "deploy/helm/vajranetra"],
  ["Containers", "Docker Compose", "deploy/docker-compose.prod.yml"],
  ["Edge", "NGINX auth_request", "integrations/gateways/nginx"],
  ["Mesh", "Envoy ext_authz", "integrations/gateways/envoy"],
  ["API gateway", "Kong plugin", "integrations/gateways/kong"],
  ["Application", "Python · Node · Java", "sdks/"],
];

export default function SystemStatusPage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [checked, setChecked] = useState<Date | null>(null);
  const load = useCallback(() => { void getHealthStatus().then((value) => { setHealth(value); setChecked(new Date()); }); }, []);
  useEffect(load, [load]);

  return (
    <Page title="System status" description="Runtime dependencies, provider selection, and deployable integration artifacts." eyebrow="Platform health" actions={<button className="ops-button" onClick={load}>Refresh checks</button>}>
      {!health ? <Empty>Checking platform health…</Empty> : <>
        <section className={`health-banner ${health.status}`}><div><span className="health-pulse" /><div><strong>{health.status === "ok" ? "All core systems operational" : "Platform degraded"}</strong><p>{health.app} · version {health.version} · {health.environment}</p></div></div><time>{checked?.toLocaleTimeString()}</time></section>

        <div className="mt-4 health-grid">
          <article><span>Database</span><strong>{health.database}</strong><p>{health.database_reachable ? "Connection verified" : "Unreachable"}</p></article>
          <article><span>Cache and event bus</span><strong>{health.cache}</strong><p>{health.cache === "redis" ? "Cross-process relay active" : "In-process development mode"}</p></article>
          <article><span>Schema</span><strong>{health.tables}</strong><p>database tables discovered</p></article>
          <article><span>Runtime</span><strong>{health.environment}</strong><p>current configuration profile</p></article>
        </div>

        <div className="mt-4 grid gap-4 xl:grid-cols-[1.1fr_1fr]">
          <Card title="Active providers"><div className="provider-status-grid">{Object.entries(health.providers).map(([key, value]) => <article key={key}><span>{key.replaceAll("_", " ")}</span><strong>{value}</strong><i className="ops-state good">ACTIVE</i></article>)}</div></Card>
          <Card title="Deployment surfaces"><div className="artifact-list">{ARTIFACTS.map(([type, name, path]) => <article key={name}><div><span>{type}</span><strong>{name}</strong></div><code>{path}</code></article>)}</div></Card>
        </div>
      </>}
    </Page>
  );
}
