import { useEffect, useState } from "react";
import { getOAuthProviders, getSCIMGroups, getSCIMUsers, type OAuthProvider, type SCIMUser } from "../api/operations";
import { triggerVoiceAlert, apiErrorMessage } from "../api/client";
import Page, { Card, Empty } from "../components/layout/Page";

const GATEWAYS = [
  { name: "Envoy ext_authz", mode: "HTTP authorization filter", endpoint: "/api/gateways/envoy/ext_authz", status: "Ready" },
  { name: "NGINX auth_request", mode: "Subrequest policy check", endpoint: "/api/gateways/nginx/auth", status: "Ready" },
  { name: "Kong plugin", mode: "Lua verification callback", endpoint: "/api/gateways/kong/verify", status: "Ready" },
  { name: "Drop-in proxy", mode: "Zero-code upstream protection", endpoint: "python -m app.dropin", status: "Ready" },
];

export default function IntegrationsPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([]);
  const [users, setUsers] = useState<SCIMUser[]>([]);
  const [groups, setGroups] = useState<Record<string, unknown>[]>([]);
  const [copied, setCopied] = useState("");
  const [twilioBusy, setTwilioBusy] = useState(false);
  const [twilioMsg, setTwilioMsg] = useState("");
  const [twilioErr, setTwilioErr] = useState("");

  useEffect(() => {
    void Promise.allSettled([getOAuthProviders(), getSCIMUsers(), getSCIMGroups()]).then(([p, u, g]) => {
      if (p.status === "fulfilled") setProviders(p.value);
      if (u.status === "fulfilled") setUsers(u.value.Resources);
      if (g.status === "fulfilled") setGroups(g.value.Resources);
    });
  }, []);

  async function copy(value: string) {
    await navigator.clipboard.writeText(value);
    setCopied(value);
    window.setTimeout(() => setCopied(""), 1400);
  }

  async function testTwilioCall() {
    setTwilioBusy(true);
    setTwilioMsg("");
    setTwilioErr("");
    try {
      const res = await triggerVoiceAlert(1, "Critical");
      setTwilioMsg(`Twilio Call Triggered: ${res.status} (SID: ${res.call_sid})`);
    } catch (err) {
      setTwilioErr(apiErrorMessage(err, "Twilio call failed. Ensure TWILIO_* credentials are set in .env"));
    } finally {
      setTwilioBusy(false);
    }
  }

  return (
    <Page title="Integrations" description="Identity provisioning and gateway enforcement points connected to the same policy decision plane." eyebrow="Control plane fabric">
      <section className="integration-hero">
        <div><span>Integration posture</span><h2>One decision plane.<br />Four enforcement paths.</h2></div>
        <p>Every gateway strips spoofed identity headers, asks the PDP, and forwards only cryptographically asserted context.</p>
      </section>

      <div className="mt-4 integration-grid">
        {GATEWAYS.map((gateway, index) => <article key={gateway.name} className={index === 0 ? "featured" : ""}><div className="integration-index">0{index + 1}</div><span className="ops-state good">{gateway.status}</span><h2>{gateway.name}</h2><p>{gateway.mode}</p><code>{gateway.endpoint}</code><button onClick={() => copy(gateway.endpoint)}>{copied === gateway.endpoint ? "Copied" : "Copy endpoint"}</button></article>)}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card title="Twilio Voice Alerts">
          <p className="text-sm text-slate-600 mb-3">
            Outbound critical incident voice calling integration powered by Twilio and ElevenLabs.
          </p>
          <button
            onClick={testTwilioCall}
            disabled={twilioBusy}
            className="w-full rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50"
          >
            {twilioBusy ? "Triggering Call…" : "Test Twilio Call"}
          </button>
          {twilioMsg && (
            <p className="mt-2 text-xs text-emerald-700 bg-emerald-50 p-2 rounded border border-emerald-200">
              {twilioMsg}
            </p>
          )}
          {twilioErr && (
            <p className="mt-2 text-xs text-red-700 bg-red-50 p-2 rounded border border-red-200">
              {twilioErr}
            </p>
          )}
        </Card>

        <Card title="Single sign-on providers">
          {providers.length === 0 ? <Empty>No live OAuth provider credentials are configured. Google, GitHub, and Keycloak support is installed.</Empty> : <div className="provider-list">{providers.map((provider, index) => { const name = provider.display_name ?? provider.name ?? provider.provider ?? provider.id ?? `Provider ${index + 1}`; return <article key={name}><div className="provider-mark">{name.slice(0, 2).toUpperCase()}</div><div><strong>{name}</strong><p>{provider.type ?? "OAuth 2.0 / OIDC"}</p></div><span className="ops-state good">Enabled</span></article>; })}</div>}
        </Card>

        <Card title={`SCIM directory (${users.length} users · ${groups.length} groups)`}>
          <div className="scim-endpoint"><div><span>Base URL</span><code>/scim/v2</code></div><button onClick={() => copy(`${location.origin}/scim/v2`)}>Copy URL</button></div>
          {users.length === 0 ? <Empty>No directory records returned.</Empty> : <div className="ops-table-wrap mt-4"><table><thead><tr><th>Directory identity</th><th>Role</th><th>State</th></tr></thead><tbody>{users.slice(0, 12).map((user) => <tr key={user.id}><td><strong>{user.displayName ?? user.userName}</strong><small>{user.emails?.[0]?.value ?? user.userName}</small></td><td>{user.roles?.[0]?.value ?? "user"}</td><td><span className={`ops-state ${user.active ? "good" : "danger"}`}>{user.active ? "ACTIVE" : "DISABLED"}</span></td></tr>)}</tbody></table></div>}
        </Card>
      </div>
    </Page>
  );
}
