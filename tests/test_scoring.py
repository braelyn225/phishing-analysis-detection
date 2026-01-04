from phishguard.scoring import Finding, score_findings


def test_score_bands():
    score, label = score_findings([Finding("a", 10, "x")])
    assert label == "LOW"

    score, label = score_findings([Finding("a", 40, "x")])
    assert label == "MEDIUM"

    score, label = score_findings([Finding("a", 80, "x")])
    assert label == "HIGH"
