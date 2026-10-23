from aiops.detector import (detect_anomaly, make_report, error_rate, zscore,
                            evaluate, baseline_from_history)


# --- tests d'origine (conservés) ---
def test_threshold():
    assert not detect_anomaly(2)
    assert detect_anomaly(3)


def test_approval_required():
    assert make_report(4, [], 'pending')['human_approval_required'] is True


# --- calculs de base ---
def test_error_rate_without_traffic_is_zero():
    assert error_rate(0, 0) == 0.0
    assert error_rate(5, 10) == 0.5


def test_zscore_flat_baseline_uses_floor():
    # Baseline parfaitement plate à 0 : sans plancher, l'écart-type serait nul (division par 0).
    assert zscore(5, [0, 0, 0, 0]) == 5.0


def test_zscore_needs_history():
    assert zscore(5, [0]) is None


# --- verdicts ---
def test_incident_is_anomaly_and_explained():
    # 20 erreurs sur 20 requêtes, alors que la baseline est à 0.
    result = evaluate(errors=20, total=20, history=[0] * 50)
    assert result["anomaly"] is True
    assert set(result["criteres_declenches"]) == {"volume", "taux", "ecart_baseline"}
    assert all(c["explication"] for c in result["details"])


def test_normal_traffic_is_normal():
    result = evaluate(errors=0, total=60, history=[0] * 50)
    assert result["verdict"] == "normal"
    assert result["anomaly"] is False


def test_few_errors_in_heavy_traffic_is_not_anomaly():
    # 4 erreurs dépassent le seuil absolu de 3, mais sur 10 000 requêtes (0,04 %) :
    # le seuil seul aurait déclenché une fausse alerte.
    assert detect_anomaly(4) is True
    result = evaluate(errors=4, total=10_000, history=[0] * 50)
    assert result["anomaly"] is False
    assert result["verdict"] == "a_surveiller"


def test_usual_error_level_is_not_anomaly():
    # Service habituellement bruyant (≈ 10 erreurs/min) : 10 erreurs n'est pas inhabituel.
    history = [8, 12, 9, 11, 10, 10, 9, 11]
    result = evaluate(errors=10, total=100, history=history)
    assert "ecart_baseline" not in result["criteres_declenches"]
    assert result["anomaly"] is False


def test_baseline_excludes_current_window():
    points = [(0, 0.0), (30, 0.0), (60, 0.0), (90, 10.0), (120, 20.0)]
    # la fenêtre courante (60 dernières secondes) est exclue de la baseline
    assert baseline_from_history(points, window_seconds=60) == [0.0, 0.0, 0.0]