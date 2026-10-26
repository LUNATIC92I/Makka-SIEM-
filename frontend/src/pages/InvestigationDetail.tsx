import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import InvestigationGraph from "../components/InvestigationGraph";
import {
  Card, ConfidenceBadge, Empty, ErrorBox, LevelBadge, Mono, Pill, ProvenanceTag, ResultStatusPill, ScoreBar, SeverityBadge,
  Spinner, SyntheticTag, Tabs, Unavailable,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { fmtDate, STATUS_LABELS, VERDICT_LABELS, verdictTone } from "../lib/format";
import GeoMap from "../maps/GeoMap";
import { api } from "../services/api";
import type { EnrichmentResult, InvestigationDetail, MapPoint } from "../types";

type TabKey = "summary" | "osint" | "timeline" | "graph" | "map" | "ai" | "events" | "notes" | "reports";

export default function InvestigationDetailPage() {
  const { id } = useParams();
  const { can } = useAuth();
  const { data: inv, error, loading, reload } = useApi<InvestigationDetail>(`/investigations/${id}`, { refreshMs: 6000 });
  const [tab, setTab] = useState<TabKey>("summary");
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label);
    setActionError(null);
    try { await fn(); await reload(true); } catch (e) { setActionError(e); } finally { setBusy(null); }
  };

  if (loading && !inv) return <Spinner />;
  if (!inv) return <ErrorBox error={error} />;
  const synthetic = inv.is_synthetic || inv.results.some((r) => r.is_synthetic);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link to="/investigations" className="text-xs text-slate-500 hover:text-cyanx-300">← Investigations</Link>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <span className="mono text-cyanx-300">{inv.reference}</span>
            <SeverityBadge severity={inv.severity} />
            <LevelBadge level={inv.risk_level} score={inv.risk_score} />
            <ConfidenceBadge level={inv.confidence_level} score={inv.confidence_score} />
            {synthetic && <SyntheticTag />}
            {inv.restricted && <Pill className="border-ink-500 text-slate-300">Accès restreint</Pill>}
          </div>
          <h1 className="mt-1 break-words text-xl font-semibold text-slate-50">{inv.title}</h1>
          <p className="text-xs text-slate-500">Créée {fmtDate(inv.created_at)} · mise à jour {fmtDate(inv.updated_at)} · traitement : {inv.pipeline_status}
            {inv.enrichment_runs > 0 && ` · passe d'enrichissement n° ${inv.enrichment_runs}`}
            {inv.superseded_results > 0 && ` (${inv.superseded_results} résultat(s) antérieur(s) conservé(s) dans l'historique Threat Intelligence)`}</p>
        </div>
        {can("investigations:write") && (
          <div className="flex flex-wrap items-center gap-2">
            <select className="input w-56" value={inv.status} onChange={(e) => act("status", () => api.patch(`/investigations/${inv.id}`, { status: e.target.value }))}>
              {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <button className="btn-ghost" disabled={!!busy} onClick={() => act("rerun", () => api.post(`/investigations/${inv.id}/run-now`))}>
              {busy === "rerun" ? "Enrichissement…" : "Relancer l'enrichissement"}
            </button>
            <button className="btn-ghost" onClick={() => act("restrict", () => api.patch(`/investigations/${inv.id}`, { restricted: !inv.restricted }))}>
              {inv.restricted ? "Lever la restriction" : "Restreindre l'accès"}
            </button>
          </div>
        )}
      </div>
      <ErrorBox error={actionError} />

      <Tabs<TabKey>
        active={tab}
        onChange={setTab}
        tabs={[
          { key: "summary", label: "Synthèse" },
          { key: "osint", label: `Résultats OSINT (${inv.results.length})` },
          { key: "timeline", label: "Chronologie" },
          { key: "graph", label: "Graphe" },
          { key: "map", label: "Carte" },
          { key: "ai", label: "Analyse IA" },
          { key: "events", label: `Événements (${inv.events.length})` },
          { key: "notes", label: `Décisions (${inv.notes.length})` },
          { key: "reports", label: `Rapports (${inv.reports.length})` },
        ]}
      />

      {tab === "summary" && <SummaryTab inv={inv} />}
      {tab === "osint" && <OsintTab inv={inv} />}
      {tab === "timeline" && <TimelineTab inv={inv} />}
      {tab === "graph" && (
        <Card title="Graphe d'investigation">{inv.relations.length ? <InvestigationGraph relations={inv.relations} /> : <Empty>Aucune relation observée.</Empty>}</Card>
      )}
      {tab === "map" && <MapTab inv={inv} />}
      {tab === "ai" && <AITab inv={inv} busy={busy} run={(p) => act("ai", () => api.post(`/investigations/${inv.id}/ai-analysis`, { provider: p }))} />}
      {tab === "events" && <EventsTab inv={inv} />}
      {tab === "notes" && <NotesTab inv={inv} onSaved={() => reload(true)} />}
      {tab === "reports" && <ReportsTab inv={inv} onCreated={() => reload(true)} />}
    </div>
  );
}

function SummaryTab({ inv }: { inv: InvestigationDetail }) {
  const src = inv.indicators.find((i) => i.role === "source");
  const ok = inv.results.filter((r) => r.status === "ok");
  const pick = <K extends "network" | "geo">(k: K) => ok.filter((r) => r.findings[k]);
  const network = pick("network");
  const geo = pick("geo");
  const reputation = ok.filter((r) => r.findings.reputation);
  const scoring = inv.scoring;
  const corr = inv.correlation;
  const ev = inv.events[0];

  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <div className="space-y-4 xl:col-span-2">
        <Card title="Indicateur principal et attribution réseau" actions={<ProvenanceTag kind="third_party" />}>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <div className="label">Adresse IP source</div>
              {src ? <Mono value={src.value} /> : <Unavailable />}
              {src?.note && <p className="mt-1 text-xs text-slate-500">{src.note}</p>}
              <div className="label mt-4">Organisation enregistrée (titulaire du bloc)</div>
              <ValueList results={network} get={(r) => r.findings.network?.registered_org} />
              <div className="label mt-3">Opérateur réseau / ASN</div>
              <ValueList results={network} get={(r) => r.findings.network?.asn ? `AS${r.findings.network.asn} ${r.findings.network.as_name ?? ""}` : undefined} />
              <div className="label mt-3">Fournisseur d'accès (si déclaré)</div>
              <ValueList results={network} get={(r) => r.findings.network?.isp} />
              <p className="mt-2 text-[11px] text-slate-500">L'organisation enregistrée n'est pas nécessairement l'utilisateur de l'adresse.</p>
            </div>
            <div>
              <div className="label">Géolocalisation estimée</div>
              <ValueList results={geo} get={(r) => {
                const g = r.findings.geo!;
                return [g.city, g.region, g.country ?? g.country_code].filter(Boolean).join(", ") + (g.accuracy_radius_km ? ` (±${g.accuracy_radius_km} km)` : "");
              }} />
              <p className="mt-1 text-[11px] text-amber-300/80">Estimation : n'identifie ni une personne ni une position exacte.</p>
              <div className="label mt-4">Réputation</div>
              {reputation.length === 0 ? <Unavailable reason="aucune source de réputation n'a répondu (≠ innocuité)" /> : (
                <ul className="space-y-1 text-sm">
                  {reputation.map((r) => (
                    <li key={r.id} className="flex items-center justify-between gap-2">
                      <span className="text-slate-300">{r.source_display}{r.is_synthetic && <span className="ml-1 text-[10px] text-amber-300">DÉMO</span>}</span>
                      <span className={verdictTone(r.findings.reputation?.verdict)}>{VERDICT_LABELS[r.findings.reputation?.verdict ?? "unknown"]} {r.findings.reputation?.raw_score ? `· ${r.findings.reputation.raw_score}` : ""}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </Card>

        <Card title="Évaluation du risque" actions={<ProvenanceTag kind="computed" />}>
          {!scoring?.risk_factors ? <Empty>Calcul en attente.</Empty> : (
            <>
              <p className="mb-3 text-sm text-slate-300">{scoring.summary}</p>
              <table className="table">
                <thead><tr><th>Facteur</th><th className="w-32">Valeur</th><th>Poids</th><th>Contribution</th><th>Justification</th></tr></thead>
                <tbody>
                  {scoring.risk_factors.map((f) => (
                    <tr key={f.key}>
                      <td className="whitespace-nowrap">{f.label}</td>
                      <td>{f.value == null ? <span className="text-xs text-slate-500">inconnu (exclu)</span> : <ScoreBar value={f.value * 100} tone="bg-orange-400" />}</td>
                      <td className="mono">{f.weight}</td>
                      <td className="mono">{f.contribution ?? "—"}</td>
                      <td className="text-xs text-slate-400">{f.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <h4 className="mt-4 text-sm font-semibold text-slate-200">Niveau de confiance — solidité des éléments</h4>
              <ul className="mt-2 space-y-1 text-xs text-slate-400">
                {scoring.confidence_factors.map((c) => <li key={c.label}><span className="text-slate-200">{c.label}</span> ({Math.round(c.value * 100)} %, poids {c.weight}) — {c.rationale}</li>)}
                {scoring.confidence_penalties.map((p) => <li key={p.label} className="text-amber-300">Pénalité : {p.label} ({p.points} pts)</li>)}
                {scoring.notes.map((n) => <li key={n} className="text-slate-500">• {n}</li>)}
              </ul>
            </>
          )}
        </Card>

        <Card title="Faits établis (attribués à leur source)" actions={<ProvenanceTag kind="third_party" />}>
          {!corr?.facts?.length ? <Empty>Aucun fait collecté.</Empty> : (
            <ul className="space-y-1.5 text-sm">
              {corr.facts.map((f, i) => (
                <li key={i} className="flex gap-2"><span className="mono shrink-0 text-xs text-slate-500">[{f.evidence_ids.join(",")}]</span><span className={f.category === "absence" ? "text-slate-500" : "text-slate-300"}>{f.statement}</span>{f.is_synthetic && <span className="text-[10px] text-amber-300">DÉMO</span>}</li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="space-y-4">
        <Card title="Événement initial" actions={<ProvenanceTag kind="observed" />}>
          {ev ? (
            <dl className="grid grid-cols-[110px_1fr] gap-y-1 text-sm">
              <dt className="text-slate-500">Horodatage</dt><dd className="mono">{fmtDate(ev.event_time)}</dd>
              <dt className="text-slate-500">ID d'origine</dt><dd className="mono break-all">{ev.source_system}:{ev.original_id}</dd>
              <dt className="text-slate-500">Événement</dt><dd>{ev.title}</dd>
              <dt className="text-slate-500">Type</dt><dd>{ev.event_type}</dd>
              <dt className="text-slate-500">Source</dt><dd className="mono">{ev.src_ip ?? "—"}{ev.src_port ? `:${ev.src_port}` : ""}</dd>
              <dt className="text-slate-500">Cible</dt><dd className="mono">{ev.hostname ?? "—"} {ev.dst_ip ? `(${ev.dst_ip}${ev.dst_port ? `:${ev.dst_port}` : ""}/${ev.protocol ?? "?"})` : ""}</dd>
              <dt className="text-slate-500">Tentatives</dt><dd>{inv.events.reduce((s, e) => s + (e.attempt_count ?? 1), 0)} sur {inv.events.length} événement(s)</dd>
            </dl>
          ) : <Empty>Investigation manuelle (sans événement SIEM).</Empty>}
        </Card>
        <Card title="Indicateurs extraits">
          <ul className="space-y-1.5 text-sm">
            {inv.indicators.map((i) => (
              <li key={`${i.id}-${i.role}`} className="flex flex-wrap items-center gap-2">
                <Pill className="border-ink-500 text-slate-400">{i.type}</Pill><Mono value={i.value} />
                <span className={`text-xs ${i.scope === "public" ? "text-emerald-300" : "text-amber-300"}`}>{i.scope}</span>
                <span className="text-xs text-slate-500">{i.role}</span>
              </li>
            ))}
          </ul>
        </Card>
        {!!corr?.contradictions?.length && (
          <Card title="Contradictions entre sources">
            <ul className="space-y-1 text-sm text-amber-200">{corr.contradictions.map((c, i) => <li key={i}>{c.indicator} — {c.dimension} : {c.description}</li>)}</ul>
          </Card>
        )}
        {!!corr?.agreements?.length && (
          <Card title="Concordances">
            <ul className="space-y-1 text-sm text-emerald-200">{corr.agreements.map((c, i) => <li key={i}>{c.description}</li>)}</ul>
          </Card>
        )}
        <Card title="Éléments manquants et erreurs de collecte">
          <ul className="space-y-1 text-sm">
            {(corr?.missing ?? []).map((m) => <li key={m} className="text-slate-300">• {m}</li>)}
            {(corr?.collection_errors ?? []).map((e, i) => <li key={i} className="text-rose-300">• {e.source} ({e.indicator}) : {e.status} — {e.message}</li>)}
            {(corr?.stale ?? []).map((s, i) => <li key={`s${i}`} className="text-amber-300">• Donnée ancienne : {s.source} — {s.message}</li>)}
            {(corr?.notes ?? []).map((n) => <li key={n} className="text-slate-500">• {n}</li>)}
            {!corr?.missing?.length && !corr?.collection_errors?.length && <li className="text-slate-500">Aucun élément signalé.</li>}
          </ul>
        </Card>
      </div>
    </div>
  );
}

function ValueList({ results, get }: { results: EnrichmentResult[]; get: (r: EnrichmentResult) => string | undefined }) {
  const rows = results.map((r) => [r, get(r)] as const).filter(([, v]) => v);
  if (!rows.length) return <Unavailable />;
  return (
    <ul className="space-y-0.5 text-sm">
      {rows.map(([r, v]) => (
        <li key={r.id}><span className="text-slate-200">{v}</span> <span className="text-xs text-slate-500">— {r.source_display} [{r.evidence_id}]</span>{r.is_synthetic && <span className="ml-1 text-[10px] text-amber-300">DÉMO</span>}</li>
      ))}
    </ul>
  );
}

function OsintTab({ inv }: { inv: InvestigationDetail }) {
  const [raw, setRaw] = useState<{ id: number; data: unknown } | null>(null);
  const showRaw = async (r: EnrichmentResult) => {
    const d = await api.get<EnrichmentResult>(`/investigations/${inv.id}/results/${r.id}/raw`);
    setRaw({ id: r.id, data: d.raw });
  };
  if (!inv.results.length) return <Card><Empty>Aucune source interrogée. Activez des connecteurs OSINT ou le mode démonstration.</Empty></Card>;
  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">Chaque résultat conserve la source, l'indicateur, l'heure de consultation, la date de la donnée, une empreinte du résultat brut et un lien de consultation lorsque la source en fournit un.</p>
      {inv.results.map((r) => (
        <div key={r.id} className={`card p-4 ${r.is_synthetic ? "border-amber-700/40" : ""}`}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-xs text-slate-500">{r.evidence_id}</span>
            <span className="font-semibold text-slate-100">{r.source_display}</span>
            <ResultStatusPill status={r.status} />
            {r.is_synthetic && <SyntheticTag />}
            <span className="text-xs text-slate-500">{r.category} · amont « {r.upstream_group} » · fiabilité {r.reliability}</span>
            <span className="ml-auto mono text-xs text-slate-400">{r.indicator}</span>
          </div>
          <div className="mt-2 grid gap-2 text-xs text-slate-400 md:grid-cols-4">
            <span>Consulté : <span className="mono text-slate-300">{fmtDate(r.queried_at)}</span></span>
            <span>Donnée du : <span className="mono text-slate-300">{fmtDate(r.data_updated_at)}</span></span>
            <span>Durée : {r.duration_ms ?? "—"} ms</span>
            <span>Confiance source : {r.source_confidence ?? "non communiquée"}</span>
          </div>
          {r.status !== "ok" ? <div className="mt-2"><Unavailable reason={r.error_message} /></div> : <FindingsView r={r} />}
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs">
            {r.reference_url && <a href={r.reference_url} target="_blank" rel="noopener noreferrer" className="text-cyanx-400 hover:underline">Consulter la source ↗</a>}
            {r.raw_sha256 && <span className="mono text-slate-500">sha256 brut : {r.raw_sha256.slice(0, 16)}…</span>}
            <button className="text-slate-400 hover:text-cyanx-300" onClick={() => (raw?.id === r.id ? setRaw(null) : showRaw(r))}>{raw?.id === r.id ? "Masquer" : "Voir"} la réponse brute</button>
          </div>
          {raw?.id === r.id && <pre className="mt-2 max-h-80 overflow-auto rounded-lg bg-ink-950 p-3 text-[11px] text-slate-400">{JSON.stringify(raw.data, null, 2)}</pre>}
        </div>
      ))}
    </div>
  );
}

function FindingsView({ r }: { r: EnrichmentResult }) {
  const f = r.findings;
  return (
    <div className="mt-2 space-y-1 text-sm">
      {f.network && <div><span className="text-slate-500">Réseau : </span>{[f.network.registered_org && `org. enregistrée ${f.network.registered_org}`, f.network.asn && `AS${f.network.asn}`, f.network.as_name, f.network.isp && `FAI ${f.network.isp}`, f.network.cidr, f.network.bgp_prefix && `préfixe ${f.network.bgp_prefix}`, f.network.rir].filter(Boolean).join(" · ")}</div>}
      {f.geo && <div><span className="text-slate-500">Géolocalisation estimée : </span>{[f.geo.city, f.geo.region, f.geo.country ?? f.geo.country_code].filter(Boolean).join(", ")}{f.geo.latitude != null && ` (${f.geo.latitude}, ${f.geo.longitude})`}{f.geo.accuracy_radius_km ? ` ±${f.geo.accuracy_radius_km} km` : ""}</div>}
      {f.reputation && <div><span className="text-slate-500">Réputation : </span><span className={verdictTone(f.reputation.verdict)}>{VERDICT_LABELS[f.reputation.verdict]}</span>{f.reputation.raw_score && ` · ${f.reputation.raw_score}`}{f.reputation.last_reported_at && ` · dernier signalement ${fmtDate(f.reputation.last_reported_at)}`}{f.reputation.explanation && <div className="text-xs text-slate-500">{f.reputation.explanation}</div>}</div>}
      {!!f.resolutions?.length && <div><span className="text-slate-500">Résolutions : </span>{f.resolutions.slice(0, 10).map((x) => `${x.type} ${x.value} (${x.temporality})`).join(" · ")}</div>}
      {!!f.certificates?.length && <div><span className="text-slate-500">Certificats : </span>{f.certificates.length} — {f.certificates.slice(0, 3).map((c) => c.subject_cn).join(", ")}</div>}
      {!!f.related?.length && <div><span className="text-slate-500">Indicateurs associés : </span>{f.related.slice(0, 8).map((x) => `${x.value} (${x.relation})`).join(" · ")}</div>}
      {!!f.campaigns?.length && <div><span className="text-slate-500">Campagnes / rapports : </span>{f.campaigns.map((c) => c.name).join(" · ")}</div>}
      {f.services && <div><span className="text-slate-500">Services exposés (passif) : </span>ports {f.services.ports.join(", ")}{f.services.vulns.length ? ` · ${f.services.vulns.length} CVE déclarées` : ""}</div>}
      {f.notes?.map((n) => <div key={n} className="text-xs text-slate-500">{n}</div>)}
    </div>
  );
}

function TimelineTab({ inv }: { inv: InvestigationDetail }) {
  return (
    <Card title="Chronologie (UTC)">
      <ol className="relative ml-3 border-l border-ink-600">
        {inv.timeline.map((t, i) => (
          <li key={i} className="mb-3 ml-4">
            <span className={`absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full border border-ink-900 ${t.kind === "siem_event" ? "bg-amber-400" : t.provenance === "ai_generated" ? "bg-fuchsia-400" : t.provenance === "third_party" ? "bg-electric-400" : "bg-cyanx-400"}`} />
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="mono text-xs text-slate-500">{fmtDate(t.ts)}</span>
              <ProvenanceTag kind={t.provenance} />
              <span className="text-slate-200">{t.label}</span>
              <span className="mono text-xs text-slate-500">{t.detail}</span>
              {t.is_synthetic && <span className="text-[10px] text-amber-300">DÉMO</span>}
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}

function MapTab({ inv }: { inv: InvestigationDetail }) {
  const { data } = useApi<{ points: MapPoint[] }>(`/map?investigation_id=${inv.id}`);
  const points = useMemo(() => data?.points ?? [], [data]);
  return <Card title="Emplacements estimés">{points.length ? <GeoMap points={points} height={460} /> : <Empty>Aucune géolocalisation disponible (adresses internes/réservées ou aucune source de géolocalisation).</Empty>}</Card>;
}

function AITab({ inv, busy, run }: { inv: InvestigationDetail; busy: string | null; run: (provider?: string) => void }) {
  const { can } = useAuth();
  const a = inv.analysis;
  const o = a?.output;
  return (
    <div className="space-y-4">
      <Card title="Analyse assistée par IA" actions={can("ai:run") && (
        <div className="flex gap-2">
          <button className="btn-ghost" disabled={!!busy} onClick={() => run("deterministic")}>Moteur déterministe</button>
          <button className="btn-primary" disabled={!!busy} onClick={() => run(undefined)}>{busy === "ai" ? "Analyse…" : "Relancer (fournisseur configuré)"}</button>
        </div>
      )}>
        {!a ? <Empty>Aucune analyse.</Empty> : (
          <div className="space-y-2 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <ProvenanceTag kind="ai_generated" />
              <Pill className={a.status === "ok" ? "border-emerald-700 text-emerald-300" : "border-rose-700 text-rose-300"}>{a.status}</Pill>
              <span className="text-xs text-slate-400">{a.provider} / {a.model ?? "—"} · {fmtDate(a.created_at)} · données envoyées hors poste : {a.data_sent_externally ? "oui" : "non"}</span>
            </div>
            <div className="mono text-[11px] text-slate-500">Empreinte des données d'entrée : {a.input_sha256}</div>
            {a.error_message && <div className="rounded border border-amber-700/60 bg-amber-950/30 p-2 text-amber-200">{a.error_message}</div>}
            {!!a.injection_flags.length && (
              <div className="rounded border border-rose-700/60 bg-rose-950/30 p-2 text-rose-200">
                {a.injection_flags.length} tentative(s) d'injection de prompt détectée(s) dans les données analysées — traitées comme données, jamais comme instructions :
                <ul className="mt-1 text-xs">{a.injection_flags.slice(0, 5).map((f, i) => <li key={i} className="mono">{f.path} · {f.pattern} · « {f.excerpt} »</li>)}</ul>
              </div>
            )}
            {!!a.validation_issues.length && <div className="text-xs text-amber-300">Corrections de validation : {a.validation_issues.join(" ; ")}</div>}
          </div>
        )}
      </Card>
      {o && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Résumé exécutif" className="xl:col-span-2"><p className="text-sm leading-relaxed text-slate-200">{o.executive_summary}</p></Card>
          <Card title="Faits établis"><EvidenceList items={o.established_facts.map((f) => ({ text: f.statement, ids: f.evidence_ids }))} /></Card>
          <Card title="Hypothèses à vérifier">
            {o.hypotheses.length ? o.hypotheses.map((h, i) => (
              <div key={i} className="mb-3 text-sm"><div className="text-slate-200">{h.statement} <span className="mono text-xs text-slate-500">[{h.evidence_ids.join(",")}]</span></div><div className="text-xs text-slate-400">{h.rationale}</div><div className="text-xs text-cyanx-300">Vérification : {h.how_to_verify}</div></div>
            )) : <Empty>Aucune hypothèse.</Empty>}
          </Card>
          <Card title="Hypothèses alternatives"><ul className="space-y-2 text-sm">{o.alternative_hypotheses.map((h, i) => <li key={i}><div className="text-slate-200">{h.statement}</div><div className="text-xs text-slate-400">{h.rationale}</div></li>)}</ul></Card>
          <Card title="Éléments contradictoires et manquants">
            <ul className="space-y-1 text-sm">
              {o.contradictions.map((c, i) => <li key={i} className="text-amber-200">• {c.description}</li>)}
              {o.missing_information.map((m, i) => <li key={`m${i}`} className="text-slate-300">• {m}</li>)}
            </ul>
          </Card>
          <Card title="Techniques MITRE ATT&CK (hypothèses)">
            {o.mitre_attack.length ? <ul className="space-y-2 text-sm">{o.mitre_attack.map((m) => <li key={m.technique_id}><span className="mono text-cyanx-300">{m.technique_id}</span> {m.name}<div className="text-xs text-slate-400">{m.justification}</div></li>)}</ul> : <Empty>Aucune technique justifiée par les preuves.</Empty>}
          </Card>
          <Card title="Attribution">
            {o.threat_actor_attribution.length ? o.threat_actor_attribution.map((t) => <div key={t.actor} className="text-sm">{t.actor} — confiance {t.confidence} [{t.evidence_ids.join(",")}] · alternatives : {t.alternatives.join(", ")}</div>)
              : <p className="text-sm text-slate-400">Aucune attribution : les éléments ne le justifient pas. Une adresse IP ne permet pas d'attribuer une attaque à une personne, un groupe ou un pays.</p>}
          </Card>
          <Card title="Risque et confiance">
            <p className="text-sm"><b>Risque {o.estimated_risk.level}</b> — <span className="text-slate-400">{o.estimated_risk.rationale}</span></p>
            <p className="mt-2 text-sm"><b>Confiance {o.confidence.level}</b> — <span className="text-slate-400">{o.confidence.rationale}</span></p>
          </Card>
          <Card title="Actions recommandées (validation humaine requise)">
            <ul className="space-y-1.5 text-sm">{o.recommended_actions.map((x, i) => <li key={i}><Pill className="mr-2 border-ink-500 text-slate-300">{x.priority}</Pill>{x.action}</li>)}</ul>
          </Card>
          <Card title="Références et limites" className="xl:col-span-2">
            <ul className="mb-3 space-y-0.5 text-xs">{o.references.map((r) => <li key={r.evidence_id}><span className="mono text-slate-500">{r.evidence_id}</span> {r.source} {r.url && <a className="text-cyanx-400" href={r.url} target="_blank" rel="noopener noreferrer">{r.url}</a>}</li>)}</ul>
            <ul className="space-y-0.5 text-xs text-slate-400">{o.limitations.map((l, i) => <li key={i}>• {l}</li>)}</ul>
          </Card>
        </div>
      )}
    </div>
  );
}

const EvidenceList = ({ items }: { items: { text: string; ids: string[] }[] }) => (
  items.length ? <ul className="space-y-1.5 text-sm">{items.map((x, i) => <li key={i}><span className="mono mr-1 text-xs text-slate-500">[{x.ids.join(",")}]</span>{x.text}</li>)}</ul> : <Empty>—</Empty>
);

function EventsTab({ inv }: { inv: InvestigationDetail }) {
  return (
    <div className="space-y-3">
      {inv.events.map((e) => (
        <Card key={e.id} title={<span>{e.title} {e.is_synthetic && <SyntheticTag />}</span>} actions={<ProvenanceTag kind="observed" />}>
          <div className="mb-2 grid gap-2 text-xs text-slate-400 md:grid-cols-4">
            <span>ID d'origine : <span className="mono text-slate-200">{e.source_system}:{e.original_id}</span></span>
            <span>Horodatage : <span className="mono text-slate-200">{fmtDate(e.event_time)}</span></span>
            <span>Reçu : <span className="mono">{fmtDate(e.received_at)}</span> ({e.ingest_method})</span>
            <span>Sévérité : {e.severity} (brute : {e.severity_raw ?? "—"})</span>
          </div>
          <div className="mono mb-2 text-[11px] text-slate-500">sha256 du contenu brut : {e.raw_sha256}</div>
          <pre className="max-h-96 overflow-auto rounded-lg bg-ink-950 p-3 text-[11px] text-slate-400">{JSON.stringify(e.raw, null, 2)}</pre>
        </Card>
      ))}
      {!inv.events.length && <Card><Empty>Aucun événement SIEM.</Empty></Card>}
    </div>
  );
}

function NotesTab({ inv, onSaved }: { inv: InvestigationDetail; onSaved: () => void }) {
  const { can } = useAuth();
  const [content, setContent] = useState("");
  const [kind, setKind] = useState<"note" | "decision">("decision");
  const [err, setErr] = useState<unknown>(null);
  const save = async () => {
    try { await api.post(`/investigations/${inv.id}/notes`, { kind, content }); setContent(""); onSaved(); } catch (e) { setErr(e); }
  };
  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Card title="Décisions et notes de l'analyste" className="xl:col-span-2">
        {inv.notes.length ? (
          <ul className="space-y-3">{inv.notes.map((n) => (
            <li key={n.id} className="rounded-lg border border-ink-700 p-3 text-sm"><div className="mb-1 text-xs text-slate-500">{fmtDate(n.created_at)} · {n.author} · <span className="uppercase">{n.kind}</span></div><div className="whitespace-pre-wrap text-slate-200">{n.content}</div></li>
          ))}</ul>
        ) : <Empty>Aucune décision enregistrée.</Empty>}
      </Card>
      {can("investigations:write") && (
        <Card title="Ajouter">
          <select className="input mb-2" value={kind} onChange={(e) => setKind(e.target.value as "note" | "decision")}><option value="decision">Décision</option><option value="note">Note</option></select>
          <textarea className="input h-40" value={content} onChange={(e) => setContent(e.target.value)} placeholder="Ex. : blocage périmétrique validé, ticket CHG-1234…" />
          <ErrorBox error={err} />
          <button className="btn-primary mt-2" disabled={!content.trim()} onClick={save}>Enregistrer (journalisé)</button>
        </Card>
      )}
    </div>
  );
}

function ReportsTab({ inv, onCreated }: { inv: InvestigationDetail; onCreated: () => void }) {
  const { can } = useAuth();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [verify, setVerify] = useState<Record<number, string>>({});
  const create = async (kind: string, format: string) => {
    setBusy(true);
    try { await api.post(`/investigations/${inv.id}/reports`, { kind, format }); onCreated(); } catch (e) { setErr(e); } finally { setBusy(false); }
  };
  return (
    <Card title="Rapports" actions={can("reports:write") && (
      <div className="flex flex-wrap gap-2">
        <button className="btn-primary" disabled={busy} onClick={() => create("technical", "pdf")}>PDF technique</button>
        <button className="btn-ghost" disabled={busy} onClick={() => create("executive", "pdf")}>PDF synthèse</button>
        <button className="btn-ghost" disabled={busy} onClick={() => create("technical", "json")}>Export JSON</button>
      </div>
    )}>
      <ErrorBox error={err} />
      {inv.reports.length ? (
        <table className="table">
          <thead><tr><th>Fichier</th><th>Type</th><th>Généré (UTC)</th><th>SHA-256</th><th /></tr></thead>
          <tbody>{inv.reports.map((r) => (
            <tr key={r.id}>
              <td className="mono">{r.file_name}</td><td>{r.kind} / {r.format}</td><td className="mono">{fmtDate(r.created_at)}</td>
              <td className="mono text-xs text-slate-500">{r.sha256.slice(0, 20)}…</td>
              <td className="whitespace-nowrap text-right">
                <button className="btn-ghost mr-2" onClick={() => api.download(`/reports/${r.id}/download`, r.file_name)}>Télécharger</button>
                <button className="btn-ghost" onClick={async () => { const v = await api.get<{ valid: boolean }>(`/reports/${r.id}/verify`); setVerify({ ...verify, [r.id]: v.valid ? "✓ intègre" : "✗ modifié" }); }}>Vérifier</button>
                {verify[r.id] && <span className={`ml-2 text-xs ${verify[r.id].startsWith("✓") ? "text-emerald-300" : "text-rose-300"}`}>{verify[r.id]}</span>}
              </td>
            </tr>
          ))}</tbody>
        </table>
      ) : <Empty>Aucun rapport généré.</Empty>}
    </Card>
  );
}
