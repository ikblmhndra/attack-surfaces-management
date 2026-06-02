import pytest

web_crawl_worker = pytest.importorskip("workers.crawler.web_crawl_worker")
_endpoint_flags = web_crawl_worker._endpoint_flags
_endpoint_score = web_crawl_worker._endpoint_score


def test_endpoint_score_prioritizes_high_signal_sources():
    endpoint = {
        "url": "https://example.com/api/v1/users?id=1",
        "source": "katana+gau+ffuf",
        "status_class": "ok",
        "content_type": "application/json",
    }

    flags = _endpoint_flags(endpoint["url"])
    score, reasons = _endpoint_score(endpoint, flags)

    assert score >= 80
    assert "api_path" in reasons
    assert "query_params" in reasons
    assert "fuzz_discovered" in reasons
    assert "json" in reasons


def test_endpoint_score_keeps_low_signal_static_pages_low():
    endpoint = {
        "url": "https://example.com/about",
        "source": "katana",
        "status_class": "ok",
        "content_type": "text/html",
    }

    flags = _endpoint_flags(endpoint["url"])
    score, reasons = _endpoint_score(endpoint, flags)

    assert score < 25
    assert reasons == ["ok"]
