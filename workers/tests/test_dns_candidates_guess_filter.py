from workers.discovery.dns_candidates import GENERATED_ONLY_SOURCES, is_unconfirmed_generated_guess


def test_pure_bruteforce_miss_is_pruned():
    assert is_unconfirmed_generated_guess({"dns_bruteforce"}, "unresolved") is True


def test_pure_permutation_miss_is_pruned():
    assert is_unconfirmed_generated_guess({"dns_permutation"}, "unresolved") is True


def test_both_generated_sources_miss_is_pruned():
    assert is_unconfirmed_generated_guess({"dns_bruteforce", "dns_permutation"}, "unresolved") is True


def test_generated_source_that_resolved_is_kept():
    # liveness_status alive/dns_only means it actually resolved -- don't prune
    assert is_unconfirmed_generated_guess({"dns_bruteforce"}, "alive") is False
    assert is_unconfirmed_generated_guess({"dns_permutation"}, "dns_only") is False


def test_passive_source_corroboration_is_kept_even_if_unresolved():
    # A dangling CNAME found by crt.sh/subfinder is still takeover-relevant signal.
    assert is_unconfirmed_generated_guess({"dns_bruteforce", "crtsh"}, "unresolved") is False
    assert is_unconfirmed_generated_guess({"subfinder"}, "unresolved") is False


def test_no_sources_is_never_pruned():
    assert is_unconfirmed_generated_guess(set(), "unresolved") is False
    assert is_unconfirmed_generated_guess(None, "unresolved") is False


def test_generated_only_sources_constant():
    assert GENERATED_ONLY_SOURCES == {"dns_bruteforce", "dns_permutation"}
