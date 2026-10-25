import copy
from datetime import timedelta

from app.core.timeutil import utc_now
from app.scoring.engine import EventEvidence, ReputationEvidence, ScoringInput, compute, effective_independent_sources
from app.services.app_settings import DEFAULTS

CFG = DEFAULTS["scoring"]
ASSETS = DEFAULTS["assets"]
EV = [EventEvidence("high", "authentication_failure_burst", "Connexions suspectes répétées", 48, "srv-web-01", "10.0.0.5")]


def rep(source, group, verdict="malicious", score=90.0, rel=0.7, days=3):
    return ReputationEvidence(source, group, rel, verdict, score, utc_now() - timedelta(days=days))


def base(**kw):
    defaults = dict(events=EV, reputation=[], categories_answered={"network", "geolocation", "reputation"})
    defaults.update(kw)
    return ScoringInput(**defaults)


def test_risk_and_confidence_are_separate_and_explained():
    out = compute(base(reputation=[rep("a", "g1"), rep("b", "g2")]), CFG, ASSETS)
    assert out["risk_score"] is not None and out["confidence_score"] is not None
    assert {f["key"] for f in out["risk_factors"]} == set(CFG["risk_weights"])
    assert all(f["rationale"] for f in out["risk_factors"])
    assert "confiance" in out["summary"] and "risque" in out["summary"].lower()


def test_duplicate_upstream_does_not_raise_confidence():
    independent = compute(base(reputation=[rep("a", "g1"), rep("b", "g2")]), CFG, ASSETS)
    duplicated = compute(base(reputation=[rep("a", "g1"), rep("mirror", "g1")]), CFG, ASSETS)
    single = compute(base(reputation=[rep("a", "g1")]), CFG, ASSETS)
    assert duplicated["confidence_score"] == single["confidence_score"]
    assert independent["confidence_score"] > duplicated["confidence_score"]


def test_known_overlap_is_discounted():
    total, notes = effective_independent_sources({"virustotal-aggregate": 0.75, "abusech": 0.8}, CFG["overlapping_groups"], 0.5)
    assert abs(total - (0.8 + 0.75 * 0.5)) < 1e-9 and notes


def test_contradictions_stale_errors_reduce_confidence():
    clean = compute(base(reputation=[rep("a", "g1"), rep("b", "g2")]), CFG, ASSETS)
    messy = compute(base(reputation=[rep("a", "g1"), rep("b", "g2")], contradictions=2, stale_results=1, errors=2), CFG, ASSETS)
    assert messy["confidence_score"] == clean["confidence_score"] - 20 - 5 - 6
    assert clean["risk_score"] == messy["risk_score"]  # risk unaffected by evidence quality


def test_absence_of_signal_is_not_benign():
    no_rep = compute(base(categories_answered={"network"}), CFG, ASSETS)
    rep_factor = next(f for f in no_rep["risk_factors"] if f["key"] == "reputation")
    assert rep_factor["value"] is None and "pas une preuve d'innocuité" in rep_factor["rationale"]
    benign = compute(base(reputation=[rep("a", "g1", "benign", 0.0)]), CFG, ASSETS)
    assert benign["risk_score"] < no_rep["risk_score"]


def test_weights_are_configurable():
    cfg = copy.deepcopy(CFG)
    cfg["risk_weights"] = {k: 0.0 for k in cfg["risk_weights"]} | {"reputation": 1.0}
    out = compute(base(reputation=[rep("a", "g1", score=40.0)]), cfg, ASSETS)
    assert out["risk_score"] == 40.0


def test_asset_criticality_and_synthetic_note():
    out = compute(base(synthetic_used=True), CFG, {"default_criticality": "low", "patterns": {"srv-*": "critical"}})
    crit = next(f for f in out["risk_factors"] if f["key"] == "target_criticality")
    assert crit["value"] == 1.0 and any("DÉMONSTRATION" in n for n in out["notes"])
