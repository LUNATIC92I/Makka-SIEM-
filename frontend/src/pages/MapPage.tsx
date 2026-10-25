import { useState } from "react";
import { Card, Empty, ErrorBox, Spinner } from "../components/ui";
import { useApi } from "../hooks/useApi";
import GeoMap, { setTilesEnabled, tilesEnabled } from "../maps/GeoMap";
import { fmtDate } from "../lib/format";
import type { MapPoint } from "../types";

export default function MapPage() {
  const { data, error, loading } = useApi<{ points: MapPoint[]; warning: string }>("/map");
  const [tiles, setTiles] = useState(tilesEnabled());
  if (loading && !data) return <Spinner />;
  if (!data) return <ErrorBox error={error} />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-50">Cartographie</h1>
          <p className="text-sm text-slate-400">{data.points.length} emplacement(s) estimé(s)</p>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300" title="Le fond OpenStreetMap envoie des requêtes à un serveur externe">
          <input type="checkbox" checked={tiles} onChange={(e) => { setTiles(e.target.checked); setTilesEnabled(e.target.checked); }} />
          Fond de carte détaillé en ligne (OpenStreetMap)
        </label>
      </div>
      <Card>{data.points.length ? <GeoMap points={data.points} height={560} tiles={tiles} /> : <Empty>Aucune géolocalisation disponible.</Empty>}</Card>
      {!!data.points.length && (
        <Card title="Relations temporelles source → cible">
          <table className="table">
            <thead><tr><th>Indicateur</th><th>Estimation</th><th>Source</th><th>Investigation</th><th>Cibles</th><th>Événements (UTC)</th></tr></thead>
            <tbody>{data.points.map((p, i) => (
              <tr key={i}><td className="mono text-cyanx-300">{p.indicator}{p.is_synthetic && <span className="ml-1 text-[10px] text-amber-300">DÉMO</span>}</td>
                <td>{[p.city, p.region, p.country].filter(Boolean).join(", ")}</td><td>{p.source}</td><td className="mono">{p.investigation_reference}</td>
                <td>{p.targets.join(", ")}</td><td className="mono text-xs">{p.event_times.map(fmtDate).join(" → ")}</td></tr>
            ))}</tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
