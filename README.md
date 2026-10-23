# TECHCORP — TP intégrateur DevSecOps & AIOps

Mission SRE sur l'API fictive **Orders API** : sécuriser la livraison (Mission A), détecter et
qualifier l'incident **INC-2026-1042** (Mission B), l'investiguer avec un LLM local sous contrôle
humain (Mission C), puis le restaurer (Mission D).

> Projet de laboratoire. Aucun secret réel, aucune action sur une production. Les services
> n'écoutent que sur `127.0.0.1`.

## Architecture

```
Développeur → branche + PR → GitHub Actions (Pytest, Gitleaks, Trivy fs, Trivy image) → Quality gate
                                                                                           │ obligatoire pour fusionner sur main
API FastAPI (/orders, /health, /metrics) → Prometheus (collecte 5 s, règle ElevatedHTTP500) → Grafana
            │ logs                                     │ métriques
            └──────────────► aiops/detector.py ◄───────┘   verdict explicable (volume, taux, z-score)
                                      │
                             aiops/investigate.py → preuves filtrées et masquées → Ollama (local)
                                      │
                    reports/report.json + reports/incident-report.md → approbation humaine (SRE)
```

## Index des livrables

| Livrable | Emplacement |
|---|---|
| Registre des risques (A1) | [`docs/registre-risques.md`](docs/registre-risques.md) |
| Workflow CI/CD de contrôle (A2) | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Quality gate documenté (A3) | [`docs/quality-gate.md`](docs/quality-gate.md) |
| Preuve « échec sécurité » puis « succès » (A4) | Pipeline #3 (vulnérabilités image) puis #4 ; PR #1 (secret fictif bloqué, puis vert) |
| Secrets Actions, GITHUB_TOKEN, Kubernetes Secrets (A5) | [`docs/securite-ci.md`](docs/securite-ci.md) |
| Dashboard Grafana provisionné (B2) | [`monitoring/grafana/`](monitoring/grafana/) |
| Seuil vs détection statistique (B4), calcul du détecteur (B5) | [`docs/detection.md`](docs/detection.md) |
| Détecteur et tests | [`aiops/detector.py`](aiops/detector.py), [`tests/`](tests/) (17 tests) |
| Investigation AIOps (C1–C5) | [`aiops/investigate.py`](aiops/investigate.py) |
| Rapports d'incident | [`reports/incident-report.md`](reports/incident-report.md), [`reports/report.json`](reports/report.json) |
| Rapport IA contesté (v1) | [`reports/incident-report-v1-contestee.md`](reports/incident-report-v1-contestee.md) |
| Revue SRE, plan de restauration (D) | [`docs/revue-sre.md`](docs/revue-sre.md) |

## Prérequis

Docker Desktop, Git, Python 3.11+, VS Code. Facultatif : [Ollama](https://ollama.com) avec le
modèle `qwen2.5:1.5b` (sans Ollama, l'investigation bascule en mode simulé documenté).

## Reproduire

### 1. Lancer le laboratoire

```powershell
docker compose up --build -d
docker compose ps                                  # api, prometheus, grafana : Up
Invoke-RestMethod http://localhost:8000/health     # status : ok
python -m pip install pytest
python -m pytest -q                                # 17 passed
```

- Prometheus : http://localhost:9090 (cible `techcorp-api` dans *Status → Target health*)
- Grafana : http://localhost:3000 → Dashboards → **TECHCORP** → **TECHCORP Orders API**

### 2. Trafic normal (baseline)

```powershell
1..60 | ForEach-Object { Invoke-RestMethod http://localhost:8000/orders | Out-Null; Start-Sleep -Milliseconds 500 }
```

### 3. Déclencher l'incident (local uniquement, ne jamais commiter)

Dans `docker-compose.yml`, passer `SIMULATE_FAILURE: "true"`, puis :

```powershell
docker compose up -d --force-recreate api
foreach ($i in 1..20) { try { Invoke-WebRequest http://localhost:8000/orders -UseBasicParsing | Out-Null } catch { }; Start-Sleep -Seconds 2 }
```

Les appels sont étalés sur plusieurs collectes : `increase()` ne compte pas les erreurs arrivées
avant la création du compteur `status="500"`.

### 4. Détecter et investiguer

```powershell
$env:PYTHONIOENCODING = "utf-8"
python -m aiops.detector                           # Verdict : ANOMALIE
python -m aiops.investigate                        # ou --simulate sans Ollama
python -m aiops.investigate --approve "Nom Prénom" # enregistre la décision, n'exécute rien
docker compose logs api | Select-String "db_connection_timeout"
```

### 5. Restaurer (action humaine, après approbation)

Remettre `SIMULATE_FAILURE: "false"`, puis :

```powershell
docker compose up -d --force-recreate api
python -m aiops.detector                           # Verdict : NORMAL (après 1 à 2 minutes)
```

### 6. Nettoyer

```powershell
docker compose down
```

## Requêtes PromQL utilisées

| Indicateur | Requête |
|---|---|
| Disponibilité de la cible | `up{job="techcorp-api"}` |
| Débit par code HTTP | `sum by (status) (rate(techcorp_http_requests_total{path="/orders"}[1m]))` |
| Taux d'erreur | `100 * (sum(rate(techcorp_http_requests_total{path="/orders",status="500"}[1m])) or vector(0)) / clamp_min(sum(rate(techcorp_http_requests_total{path="/orders"}[1m])), 0.0001)` |
| Erreurs 500 sur 1 min (alerte et détecteur) | `sum(increase(techcorp_http_requests_total{status="500"}[1m]))` |
| Latence p95 | `histogram_quantile(0.95, sum by (le) (rate(techcorp_request_duration_seconds_bucket{path="/orders"}[5m])))` |
| État de l'alerte | `ALERTS{alertname="ElevatedHTTP500"}` |

## Pipeline CI/CD

| Job | Outil | Bloque si… |
|---|---|---|
| Tests | Pytest | un test échoue |
| Secrets | Gitleaks (historique complet) | un secret est détecté |
| Dépendances | Trivy `fs` | vulnérabilité HIGH/CRITICAL avec correctif |
| Image | build Docker + Trivy `image` | vulnérabilité HIGH/CRITICAL avec correctif |
| Quality gate | verdict final | un contrôle a échoué ou n'a pas tourné |

Actions épinglées par SHA de commit, `GITHUB_TOKEN` limité à `contents: read`,
`persist-credentials: false`. `main` est protégée par un ruleset : fusion par PR uniquement,
**Quality gate** obligatoire, pas de *force push*.

## Constats clés

- **Scan d'image indispensable** : `requirements.txt` était propre, mais l'image contenait
  `starlette` 0.46.2 (3 CVE HIGH, dépendance indirecte) et `setuptools` (2 CVE HIGH).
  Corrigé : starlette 1.7.0 épinglé, setuptools retiré de l'image.
- **Supprimer un secret ne suffit pas** : Gitleaks le retrouve dans l'historique. Le commit a été
  retiré de la branche ; un vrai secret devrait être révoqué.
- **Délai d'alerte** : sans `evaluation_interval`, la règle était évaluée toutes les 60 s et
  l'alerte restait en `PENDING`. Corrigé à 5 s.
- **`up` ne suffit pas** : pendant l'incident, la cible était UP à 100 % d'erreurs.
- **L'IA se trompe** : deux rapports de `qwen2.5:1.5b` contestés (hypothèse circulaire, confiance
  élevée sans preuve, preuve inventée). Voir [`docs/revue-sre.md`](docs/revue-sre.md).

## Règles de sécurité appliquées

Logs traités comme des données non fiables (délimités, filtrés, masqués, bornés) ; aucun accès du
LLM au socket Docker ni au système ; modèle exécuté localement ; aucune remédiation automatique ;
conclusions de l'IA traitées comme des hypothèses jusqu'à validation humaine.