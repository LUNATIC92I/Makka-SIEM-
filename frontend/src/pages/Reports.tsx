import { useState } from "react";
import { Link } from "react-router-dom";
import { Card, Empty, ErrorBox, Spinner, SyntheticTag } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { fmtDate } from "../lib/format";
import { api } from "../services/api";
import type { Report } from "../types";

export default function ReportsPage() {
  const { data, error, loading } = useApi<Report[]>("/reports");
  const [verify, setVerify] = useState<Record<number, boolean>>({});
  if (loading && !data) return <Spinner />;
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold text-slate-50">Rapports</h1>
      <p className="text-sm text-slate-400">Les rapports se génèrent depuis la fiche d'investigation (onglet « Rapports »). L'empreinte SHA-256 de chaque fichier est conservée pour détecter toute modification ultérieure.</p>
      <ErrorBox error={error} />
      <Card>
        {!data?.length ? <Empty>Aucun rapport.</Empty> : (
          <table className="table">
            <thead><tr><th>Investigation</th><th>Fichier</th><th>Type</th><th>Taille</th><th>Généré (UTC)</th><th>Intégrité</th><th /></tr></thead>
            <tbody>{data.map((r) => (
              <tr key={r.id}>
                <td><Link className="mono text-cyanx-300" to={`/investigations/${r.investigation_id}`}>{r.investigation_reference}</Link> {r.is_synthetic && <SyntheticTag />}<div className="max-w-[300px] truncate text-xs text-slate-500">{r.investigation_title}</div></td>
                <td className="mono text-xs">{r.file_name}</td><td>{r.kind} / {r.format.toUpperCase()}</td><td>{(r.size_bytes / 1024).toFixed(1)} Ko</td>
                <td className="mono text-xs">{fmtDate(r.created_at)}</td>
                <td className="text-xs">{r.id in verify ? (verify[r.id] ? <span className="text-emerald-300">✓ intègre</span> : <span className="text-rose-300">✗ modifié</span>) : <button className="text-cyanx-400" onClick={async () => setVerify({ ...verify, [r.id]: (await api.get<{ valid: boolean }>(`/reports/${r.id}/verify`)).valid })}>vérifier</button>}</td>
                <td className="text-right"><button className="btn-ghost" onClick={() => api.download(`/reports/${r.id}/download`, r.file_name)}>Télécharger</button></td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
