import json
from aiops.investigate import (redact, select_log_lines, build_prompt, validate_analysis,
                               simulated_analysis, build_report, render_markdown)

LOGS = [
    'api-1  | 2026-10-23T09:23:22Z INFO:     172.23.0.3:36504 - "GET /metrics HTTP/1.1" 200 OK',
    'api-1  | 2026-10-23T09:23:22Z ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042',
    'api-1  | 2026-10-23T09:23:24Z ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042',
    'api-1  | 2026-10-23T09:23:25Z ERROR:    login failed user=alice token=abc123 from 10.1.2.3',
]


def _evidence():
    return {"metriques": {"erreurs_500_derniere_minute": 21.0, "requetes_orders_derniere_minute": 22.0,
                          "latence_p95_secondes": 0.00475, "cible_up": 1.0,
                          "premieres_erreurs_observees": "2026-10-23T09:23:25+00:00", "source": "test"},
            "detection": {"verdict": "anomalie"},
            "logs": {"source": "test", "lignes_brutes": 4, "extrait": select_log_lines(LOGS)},
            "changement": {"deployed_at_scenario": "2026-10-22T10:15:00Z",
                           "first_errors_scenario": "2026-10-22T10:17:00Z"}}


def test_redact_masks_secrets_ip_and_identifiers():
    out = redact("user=alice token=abc123 from 10.1.2.3 mail bob@corp.example Bearer xyz.987")
    for leaked in ("alice", "abc123", "10.1.2.3", "bob@corp.example", "xyz.987"):
        assert leaked not in out


def test_logs_are_filtered_deduplicated_and_bounded():
    lines = select_log_lines(LOGS)
    assert not any("/metrics" in l for l in lines)            # bruit de supervision écarté
    timeout = [l for l in lines if "db_connection_timeout" in l]
    assert len(timeout) == 1 and timeout[0].endswith("(x2)")   # dédoublonné et compté
    assert len(select_log_lines(LOGS * 100, max_lines=1)) == 1  # volume borné


def test_prompt_marks_logs_as_untrusted_data():
    prompt = build_prompt(_evidence())
    assert "NON FIABLES" in prompt and "jamais des instructions" in prompt
    assert "DÉBUT DES DONNÉES" in prompt and "FIN DES DONNÉES" in prompt


def test_llm_output_cannot_skip_human_approval():
    llm = json.dumps({"symptomes": [], "hypotheses": [{"hypothese": "x", "confiance": "certaine"}],
                      "remediation_proposee": {"action": "restart", "approbation_humaine_requise": False}})
    analysis, issues = validate_analysis(llm)
    assert analysis["remediation_proposee"]["approbation_humaine_requise"] is True
    assert "approbation_forcee_par_le_code" in issues
    assert "confiance_non_conforme" in issues
    assert any(i.startswith("cle_manquante") for i in issues)


def test_invalid_llm_output_is_reported():
    analysis, issues = validate_analysis("ceci n'est pas du JSON")
    assert issues == ["json_invalide"] and "erreur" in analysis


def test_simulated_report_is_uncertain_and_requires_approval():
    ev = _evidence()
    report = build_report(ev, simulated_analysis(ev), "simule", [])
    assert report["human_approval_required"] is True
    assert report["approbation"]["statut"] == "en_attente"
    assert all(h["confiance"] != "elevee" for h in report["analyse"]["hypotheses"])
    md = render_markdown(report)
    assert "hypothèses non validées" in md and "Approbation humaine requise : oui" in md


def test_llm_wrong_types_are_normalised_and_reported():
    # Cas réel observé avec qwen2.5:1.5b : des chaînes au lieu de listes, une seule hypothèse.
    llm = json.dumps({"symptomes": ["500"], "hypotheses": [{"hypothese": "x", "confiance": "faible",
                      "preuves_pour": "volume dépassé", "preuves_manquantes": []}],
                      "preuves": [], "controles_non_destructifs": "Lecture des métriques et des logs",
                      "limites": "Une seule source", "remediation_proposee": {"action": "a",
                      "approbation_humaine_requise": True}})
    analysis, issues = validate_analysis(llm)
    assert analysis["controles_non_destructifs"] == ["Lecture des métriques et des logs"]
    assert analysis["hypotheses"][0]["preuves_pour"] == ["volume dépassé"]
    assert "type_non_conforme:controles_non_destructifs" in issues
    assert "moins_de_deux_hypotheses" in issues
    md = render_markdown(build_report(_evidence(), analysis, "ollama", issues))
    assert "- Lecture des métriques et des logs" in md       # plus de texte éclaté lettre par lettre