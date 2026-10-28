# Guide d'utilisation

## Rôles

| Rôle | Droits |
|---|---|
| `admin` | tout : connecteurs, paramètres, utilisateurs, accès à toutes les investigations (y compris restreintes), contrôles actifs |
| `analyst` | investigations (création, statut, décisions, relance), rapports, ingestion, analyse IA, audit en lecture |
| `viewer` | consultation des investigations non restreintes et des rapports |

## Mots de passe

* **Changer son mot de passe** : bouton *Changer mon mot de passe* en bas du menu. Le mot de passe actuel est
  demandé ; toutes vos sessions sont ensuite fermées et vous vous reconnectez avec le nouveau.
* **Un utilisateur a oublié son mot de passe ou son compte est verrouillé** : un administrateur ouvre
  *Paramètres, Utilisateurs et rôles* et clique *Réinitialiser le mot de passe* (ou *Déverrouiller*). Le compte est
  débloqué, ses sessions sont fermées, et l'opération figure au journal d'audit (sans le mot de passe).
* **Le seul administrateur a oublié son mot de passe** : sur l'écran de connexion, *Mot de passe oublié ?* puis
  *Ouvrir l'outil de réinitialisation*. Une fenêtre de commande liste les comptes, demande l'identifiant puis le
  nouveau mot de passe deux fois. Aucune donnée n'est supprimée. L'outil peut aussi être lancé directement :
  `Reinitialiser-mot-de-passe.cmd` dans le dossier `resources` de l'installation, ou
  `makkadi-backend.exe --data-dir "%APPDATA%\MAKKADi\data" --reset-password [identifiant]`.
  Il ne fonctionne que sur le poste qui contient les données.

Règles : 12 caractères minimum, majuscules, minuscules et au moins un chiffre.

## Parcours type (scénario de référence)

1. **Ingestion** — un connecteur SIEM collecte l'alerte (ou import *Investigations → Importer des événements JSON*,
   ou webhook signé). L'identifiant d'origine est conservé ; un second envoi du même événement est compté comme
   doublon.
2. **Extraction** — IP source/destination, ports, protocole, horodatage, sévérité, type, hôte cible, et tout
   indicateur présent dans le texte (URL, domaines, empreintes, formes « défangées »). Les adresses privées,
   réservées, de documentation, CGNAT… sont signalées et **jamais** envoyées aux sources externes.
3. **Regroupement** — les événements d'une même source dans la fenêtre configurée (60 min) rejoignent
   l'investigation ouverte ; une investigation est créée automatiquement au-delà du seuil de sévérité.
4. **Investigation OSINT** automatique en tâche de fond (*File de tâches*).
5. **Fiche d'investigation** :
   * *Synthèse* — attribution réseau (organisation enregistrée ≠ utilisateur de l'IP ; ASN/opérateur ; FAI),
     géolocalisation **estimée**, réputation par source, évaluation du risque facteur par facteur, niveau de
     confiance et ses composantes, faits attribués à leur source, contradictions, concordances, éléments manquants,
     erreurs de collecte.
   * *Résultats OSINT* — un bloc par source : statut, heure de consultation, date de la donnée, groupe d'amont,
     fiabilité, lien de consultation, empreinte et réponse brute.
   * *Chronologie* — événements SIEM, ingestion, requêtes OSINT, analyses IA, décisions, avec la provenance.
   * *Graphe* — nœuds (événements, IP, domaines, ASN, organisations, certificats, campagnes, hôtes) et liens
     qualifiés (source, date, temporalité actuelle/historique, confiance, preuve). Cliquer un lien pour ses détails.
   * *Carte* — emplacements estimés avec rayon de précision et avertissement permanent.
   * *Analyse IA* — résumé, faits établis (avec identifiants de preuve `E…`/`R…`), hypothèses à vérifier,
     hypothèses alternatives, contradictions, manques, MITRE ATT&CK (hypothèses), attribution (vide sans preuve),
     risque/confiance expliqués, actions recommandées **soumises à validation humaine**, références, limites ;
     injections de prompt détectées affichées.
   * *Événements* — contenu brut assaini et son SHA-256.
   * *Décisions* — notes et décisions de l'analyste (journalisées).
   * *Rapports* — PDF technique, PDF synthèse, export JSON ; téléchargement et vérification d'intégrité.
6. **Clôture** — changer le statut (vrai positif, faux positif, bénin) ; la décision est historisée.

## Autres pages

* **Vue d'ensemble** — compteurs, investigations prioritaires (risque puis confiance), répartition des risques,
  alertes récentes, état des connecteurs, dernières activités.
* **Centre d'investigation** — filtres : date, IP, domaine, type d'indicateur, source SIEM, sévérité, statut,
  confiance, recherche texte ; création manuelle à partir d'un indicateur.
* **Cartographie** — toutes les géolocalisations estimées et la relation temporelle source → cible ; fond hors
  ligne par défaut, fond OpenStreetMap optionnel (envoie des requêtes à un tiers).
* **Threat Intelligence** — indicateurs connus, verdicts par source, historique des observations, sources.
* **Rapports** — tous les rapports accessibles, vérification d'intégrité.
* **Connecteurs** — configuration SIEM/OSINT/IA, test de connexion, collecte immédiate.
* **File de tâches** — tâches en attente/en cours/terminées/en échec, relance.
* **Paramètres** — scoring, ingestion, actifs, rétention, utilisateurs et rôles, audit (vérification de la chaîne),
  configuration d'exécution.

## Bonnes pratiques d'interprétation

* Une géolocalisation IP n'est pas une position GPS ; VPN, proxys, réseaux mobiles, cloud et relais faussent
  l'interprétation.
* Plusieurs sources qui reprennent le même flux ne sont pas une corroboration (la confiance le reflète).
* « Aucun signalement » ≠ « inoffensif ».
* Une résolution DNS ou un certificat partagé indiquent une relation d'infrastructure, pas une participation à
  l'attaque.
* Toute action opérationnelle (blocage, isolation) reste une décision humaine.

## Habillage visuel

L'interface adopte un habillage inspiré des films de hacking : pluie de caractères en arrière-plan, effet d'écran
cathodique (lignes de balayage, vignettage, faisceau), titres à effet de parasitage, séquence de démarrage tapée sur
l'écran de connexion, radar de surveillance, flux hexadécimal et horloge UTC en tête d'écran, cadres néon.

Ces effets sont purement décoratifs : ils ne captent aucun clic et ne masquent aucune donnée. Le bouton
**Effets visuels** (en bas du menu) les active ou les désactive, le choix étant mémorisé sur le poste. Ils sont
désactivés par défaut si Windows est réglé pour réduire les animations.
