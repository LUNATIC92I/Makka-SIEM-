// End-to-end UI test against a running MAKKADi server (demo mode).
// Usage: MAKKADI_URL=http://127.0.0.1:8765/ node e2e/ui-smoke.mjs
import { chromium } from "playwright";

const BASE = process.env.MAKKADI_URL ?? "http://127.0.0.1:8765/";
const USER = "admin", PASS = "E2e-Makkadi-Test-2026";
const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); console.log(`${cond ? "ok  " : "FAIL"} ${msg}`); };

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1500, height: 950 } });
const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e)));

await page.goto(BASE);
await page.waitForSelector("#u");
if (await page.locator("#c").count()) {           // first run: create the administrator
  await page.fill("#u", USER); await page.fill("#p", PASS); await page.fill("#c", PASS);
  await page.click("button:has-text(\"Créer l'administrateur\")");
} else {
  await page.fill("#u", USER); await page.fill("#p", PASS);
  await page.click("button:has-text(\"Se connecter\")");
}
await page.waitForSelector("text=Vue d'ensemble");
check(true, "connexion");

await page.click("button:has-text(\"Charger le scénario de démonstration\")");
await page.waitForFunction(() => document.body.innerText.includes("154.73.112.25"), null, { timeout: 30000 });
check(true, "scénario de démonstration ingéré");

await page.click("nav >> text=Investigations");
const row = page.locator("tr", { hasText: "154.73.112.25" }).first();
await row.waitFor();
// wait for the background pipeline to finish
for (let i = 0; i < 40 && !(await row.innerText()).includes("completed"); i++) await page.waitForTimeout(500);
check((await row.innerText()).includes("completed"), "pipeline d'investigation terminé");
await row.click();
await page.waitForSelector("text=Indicateur principal et attribution réseau");
const body = () => page.locator("body").innerText();
check((await body()).includes("DONNÉE DE DÉMONSTRATION"), "données synthétiques signalées");
check((await body()).includes("Évaluation du risque"), "scoring affiché");
check((await body()).includes("Contradictions entre sources"), "contradictions affichées");

for (const [tab, expected] of [
  ["Résultats OSINT", "Consulter la source"], ["Chronologie", "Chronologie (UTC)"], ["Graphe", "observations qualifiées"],
  ["Carte", "Emplacements estimés"], ["Analyse IA", "Résumé exécutif"], ["Événements", "sha256 du contenu brut"],
]) {
  await page.click(`[role=tab]:has-text("${tab}")`);
  await page.waitForTimeout(800);
  const text = await body();
  check(tab !== "Résultats OSINT" ? text.includes(expected) : text.includes("Consulté"), `onglet ${tab}`);
  if (tab === "Carte") check(text.includes("n'identifient ni une personne"), "avertissement de géolocalisation visible");
  if (tab === "Analyse IA") check(text.includes("validation humaine"), "actions soumises à validation humaine");
}

await page.click("[role=tab]:has-text(\"Rapports\")");
await page.click("button:has-text(\"PDF technique\")");
await page.waitForSelector("text=_technical_", { timeout: 20000 });
await page.click("button:has-text(\"Vérifier\")");
await page.waitForSelector("text=Intègre");
check(true, "rapport PDF généré et intègre");

for (const nav of ["Cartographie", "Threat Intelligence", "Rapports", "Connecteurs", "File de tâches", "Paramètres"]) {
  await page.click(`nav >> text=${nav}`);
  await page.waitForTimeout(700);
  check(!(await body()).includes("Erreur interne"), `page ${nav}`);
}
// Password management: administrator reset, own password change, forgotten-password help.
const PASS2 = "E2e-Changement-2026";
await page.click("[role=tab]:has-text(\"Utilisateurs et rôles\")");
await page.waitForSelector("text=Créer un utilisateur");
if (!(await page.locator("td", { hasText: "e2e-analyste" }).count())) {
  const form = page.locator(".card", { hasText: "Créer un utilisateur" });
  await form.locator("input").nth(0).fill("e2e-analyste");
  await form.locator("input").nth(1).fill("Analyste-E2e-2026");
  await form.locator("button:has-text(\"Créer\")").click();
  await page.locator("td", { hasText: "e2e-analyste" }).waitFor();
}
await page.locator("tr", { hasText: "e2e-analyste" }).locator("button:has-text(\"Réinitialiser le mot de passe\")").click();
await page.fill("#pw-new", "Analyste-Reinit-2026"); await page.fill("#pw-confirm", "Analyste-Reinit-2026");
await page.click("[role=dialog] button:has-text(\"Réinitialiser\")");
await page.waitForSelector("text=réinitialisé : compte déverrouillé");
check(true, "réinitialisation du mot de passe par l'administrateur");

const changeOwn = async (from, to) => {
  await page.click("button:has-text(\"Changer mon mot de passe\")");
  await page.fill("#pw-current", from); await page.fill("#pw-new", to); await page.fill("#pw-confirm", to);
  await page.click("[role=dialog] button:has-text(\"Changer le mot de passe\")");
  await page.waitForSelector("#u");
};
await changeOwn(PASS, PASS2);
check((await body()).includes("Mot de passe modifié"), "changement de son propre mot de passe, reconnexion demandée");
await page.click("button:has-text(\"Mot de passe oublié ?\")");
check((await body()).includes("--reset-password"), "aide mot de passe oublié affichée");
await page.fill("#u", USER); await page.fill("#p", PASS2);
await page.click("button:has-text(\"Se connecter\")");
await page.waitForSelector("text=Vue d'ensemble");
await changeOwn(PASS2, PASS);   // restore, so the script can run again
check(true, "connexion avec le nouveau mot de passe");

check(pageErrors.length === 0, `aucune erreur JavaScript (${pageErrors.join(" | ")})`);
await browser.close();
if (failures.length) { console.error(`${failures.length} échec(s)`); process.exit(1); }
console.log("UI E2E : tous les contrôles sont passés");
