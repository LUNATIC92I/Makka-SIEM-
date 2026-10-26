import L from "leaflet";
import { useEffect, useRef } from "react";
import { feature } from "topojson-client";
import type { Topology } from "topojson-specification";
import countries110m from "world-atlas/countries-110m.json";
import type { MapPoint } from "../types";
import { fmtDate } from "../lib/format";

const TILE_KEY = "makkadi.map.tiles";
export const tilesEnabled = (): boolean => { try { return localStorage.getItem(TILE_KEY) === "1"; } catch { return false; } };
export const setTilesEnabled = (v: boolean) => { try { localStorage.setItem(TILE_KEY, v ? "1" : "0"); } catch { /* ignore */ } };

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
const RISK_COLOR: Record<string, string> = { critique: "#f43f5e", "élevé": "#fb923c", "modéré": "#fbbf24", faible: "#38bdf8" };

export default function GeoMap({ points, height = 520, tiles = false }: { points: MapPoint[]; height?: number; tiles?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const map = L.map(ref.current, { worldCopyJump: true, minZoom: 1, maxZoom: 8, attributionControl: true }).setView([15, 0], 2);
    if (tiles) {
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        attribution: "© OpenStreetMap", maxZoom: 8, className: "opacity-60",
      }).addTo(map);
    } else {
      // Offline basemap (Natural Earth 110m via world-atlas, public domain): no request leaves the workstation.
      const topo = countries110m as unknown as Topology;
      const geo = feature(topo, topo.objects.countries);
      L.geoJSON(geo as GeoJSON.GeoJsonObject, { style: { color: "#243047", weight: 0.7, fillColor: "#121926", fillOpacity: 1 } }).addTo(map);
      map.attributionControl.addAttribution("Fond : Natural Earth (hors ligne)");
    }
    const bounds: L.LatLngExpression[] = [];
    points.forEach((p) => {
      const color = p.is_synthetic ? "#f59e0b" : RISK_COLOR[p.risk_level ?? ""] ?? "#22d3ee";
      if (p.accuracy_radius_km) {
        L.circle([p.latitude, p.longitude], { radius: p.accuracy_radius_km * 1000, color, weight: 1, opacity: 0.5, fillOpacity: 0.06, dashArray: "4 4" }).addTo(map);
      }
      const html = `<div style="font-size:12px;line-height:1.45">
        <div style="font-family:monospace;color:#67e8f9">${escapeHtml(p.indicator)}</div>
        ${p.is_synthetic ? '<div style="color:#fbbf24;font-weight:600">DONNÉE DE DÉMONSTRATION</div>' : ""}
        <div><b>Estimation :</b> ${escapeHtml([p.city, p.region, p.country].filter(Boolean).join(", ") || "N/D")}</div>
        <div><b>Source :</b> ${escapeHtml(p.source)}, ${escapeHtml(fmtDate(p.queried_at))}</div>
        ${p.accuracy_radius_km ? `<div><b>Rayon de précision déclaré :</b> ${p.accuracy_radius_km} km</div>` : ""}
        <div><b>Investigation :</b> ${escapeHtml(p.investigation_reference ?? "")}</div>
        <div><b>Cibles :</b> ${escapeHtml(p.targets.join(", ") || "N/D")}</div>
        <div><b>Événements :</b> ${escapeHtml(p.event_times.map((t) => fmtDate(t)).join(", "))}</div>
        <div style="color:#94a3b8;margin-top:4px">Position estimée, pas une position GPS.</div></div>`;
      L.circleMarker([p.latitude, p.longitude], { radius: 6, color, weight: 2, fillColor: color, fillOpacity: 0.5 }).bindPopup(html).addTo(map);
      bounds.push([p.latitude, p.longitude]);
    });
    if (bounds.length) map.fitBounds(L.latLngBounds(bounds), { maxZoom: 4, padding: [40, 40] });
    return () => { map.remove(); };
  }, [points, tiles]);

  return (
    <div>
      <div className="mb-2 rounded-lg border border-amber-600/50 bg-amber-500/10 px-3 py-2 text-xs text-amber-200" role="note">
        Emplacements <strong>estimés</strong> à partir de bases de géolocalisation IP. Ils n'identifient ni une personne ni une position
        physique exacte. VPN, proxys, réseaux mobiles, relais, hébergements cloud et infrastructures compromises peuvent fausser
        l'interprétation. Les cercles pointillés représentent le rayon de précision déclaré par la source.
      </div>
      <div ref={ref} style={{ height }} className="rounded-lg border border-ink-700" />
    </div>
  );
}
