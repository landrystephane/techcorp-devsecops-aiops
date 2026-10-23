# Rapport d'incident INC-2026-1042

> **Statut : hypothèses non validées.** Ce rapport est une aide au diagnostic. Aucune action n'a été exécutée.

| | |
|---|---|
| Généré le | 2026-10-23T10:50:16+00:00 |
| Mode d'analyse | **ollama** (modèle `qwen2.5:1.5b`) |
| Verdict du détecteur | **anomalie** |
| Contrôle de la sortie LLM | type_non_conforme:preuves, type_non_conforme:controles_non_destructifs, type_non_conforme:limites |

## 1. Chronologie et corrélation

| Événement | Heure |
|---|---|
| Déploiement 2.4.7 (scénario) | 2026-10-22T10:15:00Z |
| Premières erreurs (scénario) | 2026-10-22T10:17:00Z |
| Redémarrage du conteneur api (laboratoire) | 2026-10-23T09:23:03 UTC |
| Premières erreurs observées (Prometheus) | 2026-10-23T09:23:53+00:00 |

Heures en UTC (heure de Paris/Varsovie = UTC+2). La proximité dans le temps entre le changement et les erreurs est une **corrélation**, pas une preuve de cause.

## 2. Observations

- Erreurs HTTP 500 (1 min, estimation `increase`) : 21.9
- Requêtes /orders (1 min, estimation `increase`) : 21.9
- Latence p95 (s) : 0.0047
- Cible UP : 1
- Logs : 442 lignes lues (docker compose logs api), 2 retenues après filtrage et masquage

## 3. Symptômes

- 22 erreur(s) HTTP 500 sur 1m (seuil 3)
- 100.2% des requêtes /orders en erreur (seuil 5)
- z-score 6.4 par rapport à une baseline moyenne de 0.69 erreur(s) par fenêtre (seuil 3.0)

## 4. Hypothèses

| Hypothèse | Confiance | Preuves pour | Preuves manquantes |
|---|---|---|---|
| Le problème provient d'une connexion timeout dans la base de données. | faible | Ligne de code dans le log indiquant une connexion timeout; Les erreurs HTTP 500 dans la métrique latence | Les logs de la base de données ne sont pas disponibles |
| Le problème est lié à une défaillance dans la réception des requêtes. | elevee | Les erreurs HTTP 500 dans la métrique requetes_orders_derniere_minute | Les logs de la base de données ne sont pas disponibles |

## 5. Contrôles non destructifs proposés

- L'examen des logs et des métriques permet de déterminer les symptômes de l'incident.

## 6. Limites

- Il est important de noter que les logs et métriques peuvent ne pas couvrir tous les aspects du problème, car ils ne sont pas disponibles pour toutes les erreurs HTTP 500.

## 7. Remédiation proposée (non exécutée)

- Action : Examiner les logs et métriques pour identifier les causes potentielles.
- Risque : Il n'y a pas de risque potentiel de défaillance du système.
- Retour arrière : Nécessite une approbation humaine.
- **Approbation humaine requise : oui**

## 8. Validation SRE

| Statut | Approuvé par | Date |
|---|---|---|
| approuvee | Landry TOUOTAP | 2026-10-23T11:03:23+00:00 |
