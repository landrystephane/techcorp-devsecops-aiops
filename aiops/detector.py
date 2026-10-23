"""Détecteur d'anomalies TECHCORP (Mission B5).

Principe : on ne se contente pas d'un seuil fixe. Le verdict combine trois critères,
calculés sur une fenêtre temporelle glissante :

1. volume  : nombre d'erreurs HTTP 500 dans la fenêtre (seuil absolu, comme l'alerte) ;
2. taux    : part des requêtes /orders en erreur (évite d'alerter sur 3 erreurs parmi 10 000) ;
3. écart   : z-score du nombre d'erreurs par rapport à une baseline glissante
             (les fenêtres précédentes), pour juger si la situation est *inhabituelle*.

Le résultat est un verdict explicable : chaque critère renvoie sa valeur, son seuil et une
phrase en français. Seule la bibliothèque standard est utilisée (pas de dépendance).
"""
import json
import statistics
import urllib.request
from urllib.parse import urlencode
from pathlib import Path

PROMETHEUS = "http://localhost:9090"
WINDOW = "1m"            # fenêtre d'observation courante
BASELINE_RANGE = 1800    # historique utilisé comme baseline : 30 minutes
STEP = 30                # un point de baseline toutes les 30 s

ERRORS_Q = 'sum(increase(techcorp_http_requests_total{{status="500"}}[{w}]))'
TOTAL_Q = 'sum(increase(techcorp_http_requests_total{{path="/orders"}}[{w}]))'
# Requête d'origine conservée pour compatibilité avec la règle ElevatedHTTP500.
QUERY = ERRORS_Q.format(w=WINDOW)

# Seuils par défaut (documentés dans docs/detection.md)
MIN_ERRORS = 3        # même seuil que l'alerte Prometheus
MIN_ERROR_RATE = 0.05 # 5 % des requêtes /orders
Z_THRESHOLD = 3.0     # 3 écarts-types au-dessus de la baseline
MIN_STD = 1.0         # écart-type plancher : une baseline à 0 erreur ne doit pas diviser par 0


# ---------------------------------------------------------------- accès Prometheus (lecture seule)
def _get(path, params):
    url = f"{PROMETHEUS}{path}?{urlencode(params)}"
    with urllib.request.urlopen(url, timeout=5) as response:
        payload = json.load(response)
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus a répondu : {payload.get('error', 'erreur inconnue')}")
    return payload["data"]["result"]


def query_value(promql):
    """Valeur instantanée d'une requête (0.0 si aucune série)."""
    series = _get("/api/v1/query", {"query": promql})
    return float(series[0]["value"][1]) if series else 0.0


def query_history(promql, seconds=BASELINE_RANGE, step=STEP):
    """Série historique [(timestamp, valeur), ...] sur les `seconds` dernières secondes."""
    import time
    end = time.time()
    series = _get("/api/v1/query_range",
                  {"query": promql, "start": end - seconds, "end": end, "step": step})
    return [(float(t), float(v)) for t, v in series[0]["values"]] if series else []


def get_error_count(window=WINDOW):
    """Nombre d'erreurs 500 dans la fenêtre (fonction d'origine, conservée)."""
    return query_value(ERRORS_Q.format(w=window))


# ---------------------------------------------------------------- calculs purs (testables)
def detect_anomaly(count, threshold=MIN_ERRORS):
    """Seuil simple d'origine : conservé, mais insuffisant seul (voir evaluate)."""
    return count >= threshold


def error_rate(errors, total):
    """Taux d'erreur entre 0 et 1 ; 0 si aucun trafic."""
    return errors / total if total > 0 else 0.0


def zscore(value, history, min_std=MIN_STD):
    """Écart de `value` à la moyenne de `history`, en nombre d'écarts-types.

    `min_std` évite une division par zéro quand la baseline est parfaitement plate
    (ex. 0 erreur pendant 30 min) : un écart-type nul rendrait la moindre erreur infinie.
    """
    if len(history) < 2:
        return None  # pas assez d'historique pour une baseline
    mean = statistics.fmean(history)
    std = max(statistics.pstdev(history), min_std)
    return (value - mean) / std


def evaluate(errors, total, history, *, min_errors=MIN_ERRORS,
             min_rate=MIN_ERROR_RATE, z_threshold=Z_THRESHOLD, window=WINDOW):
    """Verdict explicable.

    errors  : erreurs 500 dans la fenêtre courante
    total   : requêtes /orders dans la fenêtre courante
    history : erreurs par fenêtre sur la période de baseline (fenêtre courante exclue)
    """
    rate = error_rate(errors, total)
    z = zscore(errors, history)
    baseline_mean = statistics.fmean(history) if history else None

    checks = [
        {"critere": "volume", "valeur": round(errors, 2), "seuil": min_errors,
         "declenche": errors >= min_errors,
         "explication": f"{errors:.0f} erreur(s) HTTP 500 sur {window} (seuil {min_errors})."},
        {"critere": "taux", "valeur": round(rate, 4), "seuil": min_rate,
         "declenche": rate >= min_rate,
         "explication": f"{rate:.1%} des requêtes /orders en erreur (seuil {min_rate:.0%})."},
    ]
    if z is None:
        checks.append({"critere": "ecart_baseline", "valeur": None, "seuil": z_threshold,
                       "declenche": False,
                       "explication": "Historique insuffisant : pas de baseline, critère ignoré."})
    else:
        checks.append({"critere": "ecart_baseline", "valeur": round(z, 2), "seuil": z_threshold,
                       "declenche": z >= z_threshold,
                       "explication": f"z-score {z:.1f} par rapport à une baseline moyenne de "
                                      f"{baseline_mean:.2f} erreur(s) par fenêtre (seuil {z_threshold})."})

    fired = [c["critere"] for c in checks if c["declenche"]]
    volume_and_rate = "volume" in fired and "taux" in fired
    unusual = z is None or "ecart_baseline" in fired

    if volume_and_rate and unusual:
        verdict = "anomalie"
    elif fired:
        verdict = "a_surveiller"
    else:
        verdict = "normal"

    return {
        "verdict": verdict,
        "anomaly": verdict == "anomalie",
        "fenetre": window,
        "criteres_declenches": fired,
        "details": checks,
        "regle": "anomalie = volume ET taux dépassés ET (écart à la baseline OU pas d'historique)",
    }


def baseline_from_history(points, window_seconds=60):
    """Retire de l'historique les points couverts par la fenêtre courante."""
    if not points:
        return []
    last_t = points[-1][0]
    return [v for t, v in points if t <= last_t - window_seconds]


# ---------------------------------------------------------------- rapport
def make_report(count, logs, hypothesis):
    return {'incident_id': 'INC-2026-1042',
            'observations': {'http_500_last_minute': count, 'logs': logs},
            'hypothesis': hypothesis, 'checks_read_only': [], 'confidence': 'unverified',
            'human_approval_required': True}


def run():
    errors = query_value(ERRORS_Q.format(w=WINDOW))
    total = query_value(TOTAL_Q.format(w=WINDOW))
    history = baseline_from_history(query_history(ERRORS_Q.format(w=WINDOW)))
    result = evaluate(errors, total, history)

    print(f"Verdict : {result['verdict'].upper()}  (fenêtre {WINDOW}, baseline {len(history)} points)")
    for c in result["details"]:
        mark = "X" if c["declenche"] else "-"
        print(f"  [{mark}] {c['critere']:<15} {c['explication']}")
    print(f"  Règle : {result['regle']}")

    report = make_report(errors, [], 'TODO Mission C : collecte des preuves et analyse Ollama')
    report["detection"] = result
    Path('report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print("report.json généré")
    return result


if __name__ == '__main__':
    run()