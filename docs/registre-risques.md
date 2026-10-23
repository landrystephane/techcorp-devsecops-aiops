# Registre des risques — TECHCORP Orders API

Échelles : Gravité (G) et Probabilité (P) de 1 (faible) à 4 (très élevée).
Criticité = G × P. Seuil d'action immédiate : criticité ≥ 9.

| ID | Risque | Où | G | P | Criticité | Mesure corrective | Statut |
|---|---|---|---|---|---|---|---|
| R1 | Aucun contrôle de secrets : un mot de passe ou un jeton commité passerait le CI sans alerte | `ci.yml` | 4 | 3 | **12** | Scan **Gitleaks** bloquant dans le CI ; `.gitignore` (.env, *.key, *.pem) ; protection *push* GitHub | Mission A2 |
| R2 | Dépendances Python et image de base non analysées ; `python:3.11-slim` est un tag mobile qui peut changer de contenu | `Dockerfile`, `requirements.txt` | 3 | 3 | **9** | Scan **Trivy** des dépendances et de l'image ; blocage des vulnérabilités HIGH/CRITICAL corrigeables ; épingler l'image par digest | Mission A2 |
| R3 | Actions GitHub référencées par tag (`@v4`, `@v5`) : un tag peut être déplacé vers un code malveillant (attaque de la chaîne d'approvisionnement) | `ci.yml` | 4 | 2 | **8** | Épingler chaque action par **SHA de commit** ; Dependabot pour les mises à jour | Mission A2 |
| R4 | `actions/checkout` conserve par défaut le jeton `GITHUB_TOKEN` dans `.git/config`, lisible par les étapes suivantes (outils tiers) | `ci.yml` | 3 | 2 | **6** | `persist-credentials: false` ; permissions minimales déclarées par job (déjà `contents: read`) | Mission A2 |
| R5 | Grafana : accès anonyme activé et compte `admin/admin` par défaut | `docker-compose.yml` | 3 | 2 | **6** | Atténué par l'écoute sur 127.0.0.1 (lab) ; hors lab : mot de passe via `.env` non versionné, accès anonyme désactivé | Accepté pour le lab |

## Risque identifié pour la Mission C

| ID | Risque | G | P | Mesure |
|---|---|---|---|---|
| R6 | Les logs envoyés au LLM sont des données non fiables : un log piégé pourrait contenir une instruction (*prompt injection*) | 3 | 2 | Logs traités comme données, jamais comme instructions ; aucun accès du LLM au socket Docker ; validation humaine de toute action |

## Points positifs constatés

- Conteneur API exécuté par un utilisateur non-root (`USER appuser`).
- Système de fichiers en lecture seule (`read_only: true`) et `no-new-privileges`.
- Ports publiés uniquement sur 127.0.0.1.
- Jeton CI limité à `contents: read`.
- Versions des dépendances figées dans `requirements.txt`.