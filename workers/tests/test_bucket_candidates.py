from workers.discovery.bucket_candidates import generate_bucket_candidates, normalize_seed


def test_normalize_seed_strips_non_alnum():
    assert normalize_seed("Acme Corp!") == "acmecorp"
    assert normalize_seed("acme-corp") == "acme-corp"


def test_generates_bare_seed_first():
    candidates = generate_bucket_candidates(["acme"], max_names=5)
    assert candidates[0] == "acme"


def test_generates_seed_word_combinations():
    candidates = generate_bucket_candidates(["acme"], words=["backup"], max_names=10)
    assert "acme-backup" in candidates
    assert "backup-acme" in candidates


def test_bounded_by_max_names():
    candidates = generate_bucket_candidates(["acme"], max_names=3)
    assert len(candidates) <= 3


def test_no_duplicate_candidates():
    candidates = generate_bucket_candidates(["acme", "acme"], words=["backup", "backup"], max_names=50)
    assert len(candidates) == len(set(candidates))


def test_empty_seeds_yields_no_candidates():
    assert generate_bucket_candidates([], max_names=10) == []


def test_multiple_seeds_all_represented():
    candidates = generate_bucket_candidates(["acme", "widgetco"], words=["backup"], max_names=50)
    assert "acme" in candidates
    assert "widgetco" in candidates
