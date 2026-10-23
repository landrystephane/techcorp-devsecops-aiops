# Revue SRE de l'incident INC-2026-1042

## 1. Revue critique des analyses de l'IA (qwen2.5:1.5b, Ollama local)

### Rapport v1 (`reports/incident-report-v1-contestee.md`) : rejeté
- Hypothèse unique **circulaire** : « anomalie due au déclenchement de la règle ».
  La règle et le détecteur constatent le symptôme, ils n'en sont pas la cause.
- Le log `db_connection_timeout` et la livraison 2.4.7 sont ignorés.
- Sortie non conforme au schéma (texte au lieu de listes), non détectée à l'époque :
  défaut de notre validation, corrigé (`type_non_conforme`, test de non-régression).

### Rapport v2 (`reports/incident-report.md`) : partiellement retenu
| Hypothèse de l'IA | Confiance IA | Avis SRE |
|---|---|---|
| Timeout de connexion à la base de données | faible | **Retenue, à confirmer** : seule hypothèse appuyée par une preuve directe (log explicite, répété). Confiance réelle : moyenne. |
| Défaillance dans la réception des requêtes | élevée | **Rejetée** : les requêtes sont reçues et traitées (log applicatif `order_processing_failed`), la cible est UP, la latence est normale (p95 < 5 ms). Sa seule « preuve » est le symptôme. |

Autres écarts relevés : preuve inventée (« erreurs 500 dans la métrique latence » : cette métrique
ne distingue pas les codes HTTP), risque déclaré nul, version 2.4.7 non mentionnée.

**Conclusion :** l'IA a aidé à structurer, mais ses conclusions ne sont pas fiables sans relecture.
Ses sorties restent des hypothèses.

## 2. Corrélation (C1)
- Laboratoire : conteneur `api` recréé à 09:23:03 UTC (`SIMULATE_FAILURE=true`),
  premières erreurs mesurées à 09:23:53 UTC (premières requêtes à 09:23:22 UTC, non comptées par
  `increase()` car le compteur `status="500"` n'existait pas encore).
- Scénario : 2.4.7 livrée à 10:15, erreurs à 10:17.
- Corrélation temporelle forte, **causalité non démontrée** sans comparer avec 2.4.6.

## 3. Décision et plan de restauration (D25)

| Élément | Contenu |
|---|---|
| Action approuvée | Désactiver `SIMULATE_FAILURE` et recréer le conteneur `api` (équivalent laboratoire d'un rollback vers 2.4.6) |
| Approuvé par | Landry TOUOTAP, SRE (via `python -m aiops.investigate --approve`) |
| Risque | Coupure de quelques secondes de `/orders` pendant la recréation ; si la cause est ailleurs (base de données), les erreurs persistent |
| Retour arrière | Revenir à l'état précédent (`SIMULATE_FAILURE=true`), sans perte de données : l'API est sans état |
| Validation | `/health` et `/orders` répondent 200 ; taux d'erreur à 0 % ; alerte `ElevatedHTTP500` inactive ; détecteur au verdict `normal` |
| Observabilité post-changement | Surveiller le dashboard 15 minutes : taux d'erreur, débit, latence p95 |
| Post-mortem | Sous 5 jours ouvrés, sans recherche de coupable : chronologie, cause racine confirmée, actions (test de connexion à la base dans le pipeline, alerte sur `db_connection_timeout`, baseline excluant les incidents) |

## 4. Règles de sécurité respectées
- Aucune action automatique : l'IA n'a rien exécuté, l'approbation est humaine.
- Logs traités comme des données non fiables (délimités, masqués, bornés à 2 lignes utiles sur 442).
- Aucun accès du LLM à Docker ni au système ; modèle local, aucune donnée envoyée sur Internet.