# Rapport d'incident INC-2026-1042

> **Statut : hypothèses non validées.** Ce rapport est une aide au diagnostic. Aucune action n'a été exécutée.

| | |
|---|---|
| Généré le | 2026-10-23T10:42:04+00:00 |
| Mode d'analyse | **ollama** (modèle `qwen2.5:1.5b`) |
| Verdict du détecteur | **anomalie** |
| Contrôle de la sortie LLM | conforme |

## 1. Chronologie et corrélation

| Événement | Heure |
|---|---|
| Déploiement 2.4.7 (scénario) | 2026-10-22T10:15:00Z |
| Premières erreurs (scénario) | 2026-10-22T10:17:00Z |
| Redémarrage du conteneur api (laboratoire) | 2026-10-23T09:23:03.843653542Z |
| Premières erreurs observées (Prometheus) | 2026-10-23T10:40:06+00:00 |

La proximité dans le temps entre le changement et les erreurs est une **corrélation**, pas une preuve de cause.

## 2. Observations

- Erreurs HTTP 500 (1 min) : 21.899808376676702
- Requêtes /orders (1 min) : 21.899808376676702
- Latence p95 (s) : 0.004750000000000001
- Cible UP : 1.0
- Logs : 402 lignes lues (docker compose logs api), 2 retenues après filtrage et masquage

## 3. Symptômes

- 22 erreur(s) HTTP 500 sur 1m (seuil 3)
- 100.0% des requêtes /orders en erreur (seuil 5)
- z-score 21.9 par rapport à une baseline moyenne de 0.00 erreur(s) par fenêtre (seuil 3.0)

## 4. Hypothèses

| Hypothèse | Confiance | Preuves pour | Preuves manquantes |
|---|---|---|---|
| Anomalie due à un problème de déclenchement de la règle de volume et de taux dépassés. | faible | volume dépassé; taux dépassé; z-score supérieur à 3.0 | historique de déclenchement |

## 5. Contrôles non destructifs proposés

- L
- e
- c
- t
- u
- r
- e
-  
- d
- e
- s
-  
- m
- é
- t
- r
- i
- q
- u
- e
- s
-  
- e
- t
-  
- d
- e
- s
-  
- l
- o
- g
- s

## 6. Limites

- I
- l
-  
- e
- s
- t
-  
- i
- m
- p
- o
- r
- t
- a
- n
- t
-  
- d
- e
-  
- n
- o
- t
- e
- r
-  
- q
- u
- e
-  
- c
- e
- t
- t
- e
-  
- a
- n
- o
- m
- a
- l
- i
- e
-  
- a
-  
- é
- t
- é
-  
- d
- é
- t
- e
- c
- t
- é
- e
-  
- a
- p
- r
- è
- s
-  
- l
- e
-  
- d
- é
- c
- l
- e
- n
- c
- h
- e
- m
- e
- n
- t
-  
- d
- e
-  
- l
- a
-  
- r
- è
- g
- l
- e
- ,
-  
- c
- e
-  
- q
- u
- i
-  
- p
- e
- u
- t
-  
- i
- n
- d
- i
- q
- u
- e
- r
-  
- u
- n
- e
-  
- c
- a
- u
- s
- e
-  
- p
- o
- t
- e
- n
- t
- i
- e
- l
- l
- e
- m
- e
- n
- t
-  
- l
- i
- é
- e
-  
- à
-  
- l
- a
-  
- r
- è
- g
- l
- e
-  
- e
- l
- l
- e
- -
- m
- ê
- m
- e
- .

## 7. Remédiation proposée (non exécutée)

- Action : Analyse approfondie des déclencheurs de la règle de déclenchement
- Risque : Le risque est considéré comme faible car la règle a été déclenchée après l'anomalie.
- Retour arrière : Nécessite une approbation humaine
- **Approbation humaine requise : oui**

## 8. Validation SRE

| Statut | Approuvé par | Date |
|---|---|---|
| en_attente | — | — |
