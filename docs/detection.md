# Détection de l'incident — Missions B4 et B5

## B4. Seuil d'alerte ou détection d'anomalies statistique ?

La règle Prometheus `ElevatedHTTP500` est un **seuil fixe** :

    sum(increase(techcorp_http_requests_total{status="500"}[1m])) >= 3   (pendant 15 s)

| | Seuil d'alerte | Détection d'anomalies statistique |
|---|---|---|
| Question posée | « La valeur dépasse-t-elle X ? » | « La valeur est-elle **inhabituelle** pour ce service, à ce moment ? » |
| Référence | Un nombre choisi par un humain | Une **baseline** apprise sur l'historique (moyenne, écart-type, saisonnalité) |
| Contexte | Ignoré : 3 erreurs sur 10 ou sur 10 000 requêtes, c'est pareil | Pris en compte : volume de trafic, niveau d'erreurs habituel |
| Avantages | Simple, prévisible, facile à expliquer et à auditer | S'adapte au service, réduit les fausses alertes, détecte des dérives lentes |
| Limites | Fausses alertes à fort trafic, alertes ratées sous le seuil, à réajuster à la main | Besoin d'historique, plus complexe à expliquer, peut « apprendre » une situation dégradée comme normale |

Un seuil reste indispensable comme filet de sécurité simple. La détection statistique le
complète, elle ne le remplace pas. **Aucune des deux n'établit une cause** : elles disent
*qu'il se passe quelque chose*, pas *pourquoi*.

### Constat pendant le TP : le délai réel d'une alerte

L'alerte est d'abord restée en `PENDING` plus d'une minute. `prometheus.yml` ne fixait pas
`evaluation_interval`, donc Prometheus évaluait la règle **toutes les 60 s** (valeur par défaut).
Corrigé avec `evaluation_interval: 5s` : l'alerte passe en `FIRING` en une vingtaine de secondes.

    Délai maximal ≈ intervalle de collecte (5 s) + intervalle d'évaluation + durée `for` (15 s)

## B5. Le détecteur `aiops/detector.py`

Le détecteur ajoute deux critères au seuil, sur une **fenêtre temporelle** d'une minute :

| Critère | Calcul | Seuil | Pourquoi |
|---|---|---|---|
| Volume | erreurs 500 sur 1 min (`increase`) | ≥ 3 | Même base que l'alerte |
| Taux | erreurs 500 ÷ requêtes `/orders` | ≥ 5 % | 3 erreurs sur 10 000 requêtes ne sont pas un incident |
| Écart à la baseline | z-score = (valeur − moyenne) ÷ écart-type, sur les 30 dernières minutes, fenêtre courante exclue | ≥ 3 | La situation est-elle inhabituelle ? |

**Verdict :**
- `anomalie` : volume **et** taux dépassés, **et** écart à la baseline (ou pas encore d'historique) ;
- `a_surveiller` : au moins un critère dépassé, mais pas tous ;
- `normal` : aucun critère dépassé.

Chaque critère renvoie sa valeur, son seuil et une phrase d'explication : le verdict est **explicable**.

**Écart-type plancher (`MIN_STD = 1`).** Quand la baseline est parfaitement plate (0 erreur pendant
30 minutes), l'écart-type vaut 0 et la moindre erreur donnerait un z-score infini. Le plancher garde
un résultat interprétable.

**Limites connues :**
- `increase()` extrapole : la valeur est une estimation (22,27 observé pour 20 requêtes) ;
- la baseline de 30 min est courte : pas de saisonnalité (heure, jour de la semaine) ;
- si l'incident dure, il finit par entrer dans la baseline et le z-score baisse ;
- le compteur `status="500"` n'existe qu'après la première erreur : les toutes premières erreurs
  peuvent échapper à `increase()`.

## Reproduire

    python -m pytest -q          # 10 tests, sans Prometheus
    python -m aiops.detector     # nécessite le laboratoire lancé