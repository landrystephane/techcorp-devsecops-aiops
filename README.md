# TECHCORP — TP intégré DevSecOps + AIOps

## Pour les étudiants
Ce dépôt est un **squelette pédagogique**, pas une correction complète. Consulter `SUJET_TP.md` et le PDF fourni. Les TODO du détecteur et de la CI sont à réaliser.

## Lancement (Windows / Docker Desktop)
```powershell
docker compose up --build -d
docker compose ps
Invoke-RestMethod http://localhost:8000/health
Invoke-RestMethod http://localhost:8000/orders
```
Prometheus : http://localhost:9090 ; Grafana : http://localhost:3000 (accès anonyme lecture seule **uniquement pour laboratoire local**).

## Injecter la panne
Modifier `SIMULATE_FAILURE` à `true` dans `docker-compose.yml`, puis :
```powershell
docker compose up -d --force-recreate api
1..10 | ForEach-Object { try { Invoke-WebRequest http://localhost:8000/orders -UseBasicParsing } catch { Write-Host "HTTP 500 simulé" } }
python -m aiops.detector
python -m pytest -q
```
Attendre au moins un cycle de collecte avant la requête PromQL. La requête `increase(...[1m])` nécessite suffisamment d'échantillons.

## Sécurité
Ne pas utiliser de vrais secrets. API et outils liés à 127.0.0.1. Ne pas monter `/var/run/docker.sock` dans un conteneur IA. Vérifier que Docker Desktop dispose de ressources suffisantes. Supprimer les services après l'exercice : `docker compose down`.

## Travaux non fournis
L'appel Ollama, la collecte de preuves, le tableau de bord Grafana provisionné, le contrôle CI Gitleaks/Trivy, les seuils basés sur une baseline et la remédiation documentée sont à développer.
