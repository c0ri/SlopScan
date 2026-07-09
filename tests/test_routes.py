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
