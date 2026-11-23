import time

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import main
from main import CACHE_TTL, CACHE_TTL_ERROR, GITHUB_API_BASE, app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_cache():
    main._cache.clear()
    yield
    main._cache.clear()


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@respx.mock
def test_check_happy_path_with_github_signal(pypi_payload, github_repo_payload):
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(return_value=httpx.Response(200, json=github_repo_payload))
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests/commits").mock(
        return_value=httpx.Response(
            200, json=[{"sha": "x"}],
            headers={"Link": '<...&page=6484>; rel="last"'},
        )
    )

    resp = client.get("/check/pypi/requests")
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert "github_signal" in data["component_scores"]
    assert data["metadata"]["github"]["stars"] == 58000
    assert data["risk"] in ("SAFE", "CAUTION", "SUSPICIOUS", "DANGEROUS")


@respx.mock
def test_check_package_without_github_link_redistributes_weight(pypi_payload):
    # Strip the GitHub-linkable project_urls / home_page entirely.
    pypi_payload["info"]["project_urls"] = {}
    pypi_payload["info"]["home_page"] = None
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))

    resp = client.get("/check/pypi/requests")
    assert resp.status_code == 200
    data = resp.json()

    assert "github_signal" not in data["component_scores"]
    assert any("GitHub signal unavailable" in f for f in data["flags"])
    # trust_score must still be computed from the remaining signals (redistributed),
    # not silently deflated by treating the missing signal as a 0.
    assert data["trust_score"] > 0
    assert data["metadata"]["github"] is None


@respx.mock
def test_check_not_found_package():
    respx.get("https://pypi.org/pypi/definitely-not-a-real-package-xyz123/json").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://registry.npmjs.org/definitely-not-a-real-package-xyz123").mock(
        return_value=httpx.Response(404)
    )
    resp = client.get("/check/pypi/definitely-not-a-real-package-xyz123")
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is False
    assert data["risk"] == "DANGEROUS"
    assert data["trust_score"] == 0


@respx.mock
def test_github_rate_limit_uses_short_cache_ttl(pypi_payload):
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(return_value=httpx.Response(429))

    resp = client.get("/check/pypi/requests")
    assert resp.status_code == 200
    data = resp.json()
    # package itself is still found/scored — only the github enrichment is missing
    assert data["found"] is True
    assert "github_signal" not in data["component_scores"]
    assert any("GitHub signal unavailable" in f for f in data["flags"])

    # but a passing GitHub rate-limit must not lock in a degraded trust_score
    # for a full day — should get the short error TTL so it re-checks soon.
    _, expires_at = main._cache["pypi:requests"]
    remaining = expires_at - time.time()
    assert remaining <= CACHE_TTL_ERROR
    assert remaining > CACHE_TTL_ERROR - 30


@respx.mock
def test_github_no_repo_url_uses_long_cache_ttl(pypi_payload):
    # No linkable GitHub repo is a stable fact about the package, not a
    # transient failure — should keep the normal long success TTL.
    pypi_payload["info"]["project_urls"] = {}
    pypi_payload["info"]["home_page"] = None
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))

    resp = client.get("/check/pypi/requests")
    assert resp.status_code == 200

    _, expires_at = main._cache["pypi:requests"]
    remaining = expires_at - time.time()
    assert remaining > CACHE_TTL_ERROR


@respx.mock
def test_check_registry_timeout_is_unknown_not_dangerous():
    respx.get("https://pypi.org/pypi/requests/json").mock(side_effect=httpx.TimeoutException("timed out"))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))
    resp = client.get("/check/pypi/requests")
    assert resp.status_code == 200
    data = resp.json()
    # A transient registry timeout must not be scored the same as a confirmed
    # nonexistent package — that would false-positive "DANGEROUS" on real,
    # popular packages whenever the upstream registry is briefly unreachable.
    assert data["risk"] == "UNKNOWN"
    assert data["found"] is None
    assert data["risk"] != "DANGEROUS"


@respx.mock
def test_check_registry_5xx_is_unknown_not_dangerous():
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(503))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))
    resp = client.get("/check/pypi/requests")
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk"] == "UNKNOWN"
    assert data["found"] is None


def test_check_bad_ecosystem_returns_400():
    resp = client.get("/check/rubygems/somegem")
    assert resp.status_code == 400


@respx.mock
def test_check_batch(pypi_payload, github_repo_payload):
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(return_value=httpx.Response(200, json=github_repo_payload))
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests/commits").mock(return_value=httpx.Response(200, json=[]))
    respx.get("https://pypi.org/pypi/definitely-not-a-real-package-xyz123/json").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://registry.npmjs.org/definitely-not-a-real-package-xyz123").mock(
        return_value=httpx.Response(404)
    )

    resp = client.post(
        "/check/batch",
        json={
            "packages": [
                {"ecosystem": "pypi", "name": "requests"},
                {"ecosystem": "pypi", "name": "definitely-not-a-real-package-xyz123"},
            ]
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["total"] == 2
    assert data["summary"]["dangerous"] == 1


def test_check_batch_rejects_over_20():
    packages = [{"ecosystem": "pypi", "name": f"pkg{i}"} for i in range(21)]
    resp = client.post("/check/batch", json={"packages": packages})
    assert resp.status_code == 400


def test_cache_stats_and_clear():
    resp = client.get("/cache/stats")
    assert resp.status_code == 200
    assert resp.json()["cached_entries"] == 0

    resp = client.delete("/cache")
    assert resp.status_code == 200
    assert resp.json()["cleared"] is True


@respx.mock
def test_cache_ttl_short_for_not_found(pypi_payload):
    respx.get("https://pypi.org/pypi/definitely-not-a-real-package-xyz123/json").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://registry.npmjs.org/definitely-not-a-real-package-xyz123").mock(
        return_value=httpx.Response(404)
    )
    client.get("/check/pypi/definitely-not-a-real-package-xyz123")

    _, expires_at = main._cache["pypi:definitely-not-a-real-package-xyz123"]
    remaining = expires_at - time.time()
    assert remaining <= CACHE_TTL_ERROR
    assert remaining > CACHE_TTL_ERROR - 30


@respx.mock
def test_cache_ttl_long_for_success(pypi_payload, github_repo_payload):
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(return_value=httpx.Response(200, json=github_repo_payload))
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests/commits").mock(return_value=httpx.Response(200, json=[]))
    client.get("/check/pypi/requests")

    _, expires_at = main._cache["pypi:requests"]
    remaining = expires_at - time.time()
    assert remaining > CACHE_TTL_ERROR
    assert remaining <= CACHE_TTL


def _young_pypi_payload(pypi_payload, days_old):
    from datetime import datetime, timedelta, timezone
    ts = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    pypi_payload["releases"] = {"1.0.0": [{"upload_time_iso_8601": ts}]}
    return _no_github(pypi_payload)


def _no_github(pypi_payload):
    # Keep these tests about the cross-ecosystem signal only: no GitHub lookups.
    pypi_payload["info"]["project_urls"] = {}
    pypi_payload["info"]["home_page"] = None
    return pypi_payload


@respx.mock
def test_cross_ecosystem_name_clash_ignored_for_established_package(pypi_payload):
    # `requests` exists on both PyPI and npm; the PyPI one is years old.
    _no_github(pypi_payload)
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(
        return_value=httpx.Response(200, json={"name": "requests", "time": {"created": "2012-01-01T00:00:00.000Z"}, "versions": {"1.0.0": {}}})
    )
    data = client.get("/check/pypi/requests").json()
    assert data["cross_ecosystem_hit"] is True  # the fact is still reported
    assert data["component_scores"]["cross_ecosystem"] == 100
    assert not any("cross-ecosystem" in f for f in data["flags"])


@respx.mock
def test_cross_ecosystem_name_clash_still_flagged_for_young_package(pypi_payload):
    payload = _young_pypi_payload(pypi_payload, days_old=30)
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=payload))
    respx.get("https://registry.npmjs.org/requests").mock(
        return_value=httpx.Response(200, json={"name": "requests", "time": {"created": "2012-01-01T00:00:00.000Z"}, "versions": {"1.0.0": {}}})
    )
    data = client.get("/check/pypi/requests").json()
    assert data["component_scores"]["cross_ecosystem"] == 0
    assert any("cross-ecosystem confusion" in f for f in data["flags"])


@respx.mock
def test_cross_ecosystem_boundary_is_365_days(pypi_payload):
    for days, expect_flag in ((364, True), (366, False)):
        main._cache.clear()
        payload = _young_pypi_payload(dict(pypi_payload), days_old=days)
        respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=payload))
        respx.get("https://registry.npmjs.org/requests").mock(
            return_value=httpx.Response(200, json={"name": "requests", "time": {"created": "2012-01-01T00:00:00.000Z"}, "versions": {"1.0.0": {}}})
        )
        data = client.get("/check/pypi/requests").json()
        assert any("cross-ecosystem" in f for f in data["flags"]) is expect_flag, days


@respx.mock
def test_not_found_flag_does_not_claim_certainty():
    respx.get("https://pypi.org/pypi/nope-zzq/json").mock(return_value=httpx.Response(404))
    respx.get("https://registry.npmjs.org/nope-zzq").mock(return_value=httpx.Response(404))
    data = client.get("/check/pypi/nope-zzq").json()
    assert data["risk"] == "DANGEROUS"
    flag = data["flags"][0]
    assert "removed, hallucinated or never existed" in flag and "do not install" in flag


def _npm_payload(days_old, maintainers=True, author=None):
    from datetime import datetime, timedelta, timezone
    ts = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    d = {
        "name": "somepkg", "dist-tags": {"latest": "1.0.0"},
        "time": {"created": ts, "1.0.0": ts}, "versions": {"1.0.0": {}},
        "description": "x", "homepage": "https://example.com", "license": "MIT",
    }
    if maintainers:
        d["maintainers"] = [{"name": "someone"}]
    if author:
        d["author"] = {"name": author}
    return d


def _npm_flags(payload):
    with respx.mock:
        respx.get("https://registry.npmjs.org/somepkg").mock(return_value=httpx.Response(200, json=payload))
        respx.get("https://pypi.org/pypi/somepkg/json").mock(return_value=httpx.Response(404))
        main._cache.clear()
        data = client.get("/check/npm/somepkg").json()
    return data, any("No author/maintainer info" in f for f in data["flags"])


def test_npm_established_package_with_maintainers_not_flagged_for_missing_author():
    data, flagged = _npm_flags(_npm_payload(days_old=800))
    assert not flagged
    assert data["metadata"]["author"] == ""  # "author" keeps its literal meaning


def test_npm_young_package_still_penalized_for_missing_author():
    _, flagged = _npm_flags(_npm_payload(days_old=30))
    assert flagged


def test_npm_established_package_without_any_maintainer_still_flagged():
    _, flagged = _npm_flags(_npm_payload(days_old=800, maintainers=False))
    assert flagged


def test_npm_package_with_real_author_never_flagged():
    for days in (10, 800):
        _, flagged = _npm_flags(_npm_payload(days_old=days, author="A. Person"))
        assert not flagged


def test_npm_author_penalty_boundary_is_365_days():
    assert _npm_flags(_npm_payload(days_old=364))[1] is True
    assert _npm_flags(_npm_payload(days_old=366))[1] is False


def test_github_reason_text_is_plain_language():
    from main import _github_reason_text, _registry_error_text
    assert _github_reason_text("no_repo_url") == "no source repository linked"
    assert _github_reason_text("not_found") == "linked repository not found"
    assert _github_reason_text("rate_limited") == "GitHub rate limit reached"
    assert _github_reason_text("http_502") == "GitHub had a server error"
    assert _github_reason_text("http_418") == "GitHub returned an error"
    assert _registry_error_text("timeout") == "timed out"
    assert _registry_error_text("http_503") == "registry returned HTTP 503"
    assert _registry_error_text("weird") == "registry error"


@respx.mock
def test_user_facing_flags_do_not_leak_internal_codes(pypi_payload):
    pypi_payload["info"]["project_urls"] = {}
    pypi_payload["info"]["home_page"] = None
    respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))
    data = client.get("/check/pypi/requests").json()
    text = " ".join(data["flags"])
    assert "no_repo_url" not in text and "weight redistributed" not in text
    assert "no source repository linked" in text


@respx.mock
def test_registry_timeout_flag_is_plain_language_but_error_code_stays_machine_readable():
    respx.get("https://pypi.org/pypi/slowpkg/json").mock(side_effect=httpx.ReadTimeout("t"))
    respx.get("https://registry.npmjs.org/slowpkg").mock(return_value=httpx.Response(404))
    data = client.get("/check/pypi/slowpkg").json()
    assert data["risk"] == "UNKNOWN" and data["error"] == "timeout"
    assert data["flags"] == ["Registry lookup failed (timed out) — could not verify, not scored"]


@respx.mock
def test_npm_case_variant_does_not_poison_the_real_package_cache():
    # npm is case-sensitive: "React" 404s, "react" is real. A lookup of the former
    # must not leave a cached not-found verdict under the latter.
    respx.get("https://registry.npmjs.org/React").mock(return_value=httpx.Response(404))
    respx.get("https://pypi.org/pypi/React/json").mock(return_value=httpx.Response(404))
    good = {"name": "react", "dist-tags": {"latest": "1.0.0"}, "maintainers": [{"name": "m"}],
            "time": {"created": "2012-01-01T00:00:00.000Z", "1.0.0": "2012-01-01T00:00:00.000Z"},
            "versions": {"1.0.0": {}}, "description": "x", "homepage": "https://e.com", "license": "MIT"}
    respx.get("https://registry.npmjs.org/react").mock(return_value=httpx.Response(200, json=good))
    respx.get("https://pypi.org/pypi/react/json").mock(return_value=httpx.Response(404))

    assert client.get("/check/npm/React").json()["risk"] == "DANGEROUS"
    real = client.get("/check/npm/react").json()
    assert real["found"] is True and real["risk"] != "DANGEROUS"


@respx.mock
def test_pypi_cache_is_still_case_insensitive(pypi_payload):
    pypi_payload["info"]["project_urls"] = {}
    pypi_payload["info"]["home_page"] = None
    route = respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://pypi.org/pypi/Requests/json").mock(return_value=httpx.Response(200, json=pypi_payload))
    respx.get("https://registry.npmjs.org/requests").mock(return_value=httpx.Response(404))
    respx.get("https://registry.npmjs.org/Requests").mock(return_value=httpx.Response(404))
    first = client.get("/check/pypi/requests").json()
    second = client.get("/check/pypi/Requests").json()
    assert first["found"] and second["found"] and second["cached"] is True
