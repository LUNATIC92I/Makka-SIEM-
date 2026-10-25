# Mécanisme de scoring

Deux valeurs distinctes, jamais confondues :

* **Niveau de risque** (0–100) : estimation du caractère potentiellement malveillant de l'activité observée.
* **Niveau de confiance** (0–100) : solidité des éléments disponibles pour soutenir une conclusion.

Code : `backend/app/scoring/engine.py`. Paramètres : *Paramètres → Seuils et pondérations* (table `app_settings`,
clé `scoring`), chaque modification étant journalisée dans l'audit.

## Risque

Moyenne pondérée des facteurs **connus** :

| Facteur | Poids par défaut | Calcul |
|---|---|---|
| Réputation documentée | 0,35 | par **groupe d'amont** : score maximal du groupe (verdict « bénin » = 0) ; puis moyenne des groupes pondérée par la fiabilité de la source |
| Contexte de l'événement SIEM | 0,20 | sévérité normalisée (info 0,1 · low 0,3 · medium 0,5 · high 0,75 · critical 0,95) + 0,1 si la nature de l'événement est suspecte (force brute, échecs d'authentification, balayage…) |
| Fréquence des tentatives | 0,10 | `min(1, log10(tentatives) / 3)` — 1 000 tentatives = maximum |
| Criticité de la cible | 0,15 | inventaire des actifs (motifs sur nom d'hôte/IP) : low 0,25 · medium 0,5 · high 0,75 · critical 1 |
| Associations documentées | 0,15 | campagnes / rapports déclarés par des sources : `min(1, 0,3 × groupes indépendants + 0,1 × campagnes (≤3))` |
| Récence | 0,05 | dernier signalement défavorable ≤ 30 j → 1 ; ≤ 180 j → 0,5 ; au-delà → 0,1 |

**Un facteur inconnu est exclu** du calcul (et pénalise la confiance) : l'absence de signalement n'est pas une preuve
d'innocuité et ne fait donc pas baisser le risque. Niveaux : faible < 30 ≤ modéré < 55 ≤ élevé < 80 ≤ critique.

## Confiance

```
confiance = 100 × (0,45 × corroboration + 0,35 × couverture + 0,20 × part des facteurs connus) − pénalités
```

* **Corroboration indépendante** = `min(1, sources_effectives / 2)`. Les sources effectives sont la somme des
  fiabilités **par groupe d'amont** : plusieurs fournisseurs qui reprennent le même flux (même `upstream_group`)
  comptent **une seule fois**. Pour les groupes connus pour partager des données (`overlapping_groups`, ex.
  VirusTotal ↔ abuse.ch, OTX ↔ abuse.ch), le second groupe est compté avec un coefficient `overlap_discount`
  (0,5 par défaut).
* **Couverture** : part des dimensions documentées parmi réseau, géolocalisation, réputation (réputation seule si
  aucun indicateur public n'est enrichissable).
* **Pénalités** : −10 par contradiction (max −30), −5 par donnée obsolète (> 180 j, max −15), −3 par erreur de
  collecte (max −15).

Niveaux : faible < 40 ≤ moyenne < 70 ≤ élevée.

Lorsque des données synthétiques sont utilisées, une note « Calcul réalisé sur des DONNÉES DE DÉMONSTRATION » est
ajoutée.

## Explicabilité

Chaque calcul retourne, pour chaque facteur : valeur, poids, contribution en points, statut (« pris en compte » ou
« inconnu ») et justification en clair ; pour la confiance : composantes, pénalités et notes (sources dédupliquées,
recouvrements). Ces éléments sont affichés dans la fiche d'investigation et repris dans les rapports.

## Exemple (scénario de démonstration)

Sources `demo_reputation_a` et `demo_reputation_mirror` (même amont `demo-feed-1`) + `demo_reputation_b`
(amont `demo-feed-2`) → 2 groupes indépendants, la justification indique « Sources de même amont comptées une seule
fois ». Les deux géolocalisations synthétiques divergent (XA / XB) → 1 contradiction → −10 points de confiance.
