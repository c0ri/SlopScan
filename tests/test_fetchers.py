import httpx
import pytest
import respx

from main import GITHUB_API_BASE, fetch_github_signal, fetch_npm, fetch_pypi


# ---------------------------------------------------------------------------
# fetch_pypi
# ---------------------------------------------------------------------------
@respx.mock
async def test_fetch_pypi_happy_path(pypi_payload):
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=pypi_payload)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_pypi("requests", client)

    assert result["found"] is True
    assert result["name"] == "requests"
    assert result["version_count"] == 3
    assert result["project_urls"]["Source"] == "https://github.com/psf/requests"
    # author/maintainer both None in fixture -> falls back to inferred GitHub owner
    assert result["author"] == "psf (inferred from GitHub)"


@respx.mock
async def test_fetch_pypi_not_found():
    respx.get("https://pypi.org/pypi/definitely-not-real/json").mock(
        return_value=httpx.Response(404)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_pypi("definitely-not-real", client)
    assert result == {"error": "not_found"}


@respx.mock
async def test_fetch_pypi_timeout():
    respx.get("https://pypi.org/pypi/slowpkg/json").mock(side_effect=httpx.TimeoutException("timed out"))
    async with httpx.AsyncClient() as client:
        result = await fetch_pypi("slowpkg", client)
    assert result == {"error": "timeout"}


@respx.mock
async def test_fetch_pypi_author_present_wins_over_fallbacks(pypi_payload):
    pypi_payload["info"]["author"] = "Kenneth Reitz"
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=pypi_payload)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_pypi("requests", client)
    assert result["author"] == "Kenneth Reitz"


@respx.mock
async def test_fetch_pypi_maintainer_used_when_author_missing(pypi_payload):
    pypi_payload["info"]["maintainer"] = "Some Maintainer"
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=pypi_payload)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_pypi("requests", client)
    assert result["author"] == "Some Maintainer"


@respx.mock
async def test_fetch_pypi_all_author_fields_absent_returns_empty_string(pypi_payload):
    pypi_payload["info"]["project_urls"] = {}
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=pypi_payload)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_pypi("requests", client)
    assert result["author"] == ""


# ---------------------------------------------------------------------------
# fetch_npm
# ---------------------------------------------------------------------------
@respx.mock
async def test_fetch_npm_happy_path_dict_repository(npm_payload_dict_repo):
    respx.get("https://registry.npmjs.org/lodash").mock(
        return_value=httpx.Response(200, json=npm_payload_dict_repo)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_npm("lodash", client)
    assert result["found"] is True
    assert result["repository_url"] == "git+https://github.com/lodash/lodash.git"


@respx.mock
async def test_fetch_npm_happy_path_string_repository(npm_payload_string_repo):
    respx.get("https://registry.npmjs.org/lodash").mock(
        return_value=httpx.Response(200, json=npm_payload_string_repo)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_npm("lodash", client)
    assert result["repository_url"] == "github:lodash/lodash"


@respx.mock
async def test_fetch_npm_not_found():
    respx.get("https://registry.npmjs.org/definitely-not-real").mock(
        return_value=httpx.Response(404)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_npm("definitely-not-real", client)
    assert result == {"error": "not_found"}


@respx.mock
async def test_fetch_npm_timeout():
    respx.get("https://registry.npmjs.org/slowpkg").mock(side_effect=httpx.TimeoutException("timed out"))
    async with httpx.AsyncClient() as client:
        result = await fetch_npm("slowpkg", client)
    assert result == {"error": "timeout"}


@respx.mock
async def test_fetch_npm_missing_repository_field(npm_payload_dict_repo):
    del npm_payload_dict_repo["repository"]
    respx.get("https://registry.npmjs.org/lodash").mock(
        return_value=httpx.Response(200, json=npm_payload_dict_repo)
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_npm("lodash", client)
    assert result["repository_url"] == ""


# ---------------------------------------------------------------------------
# fetch_github_signal
# ---------------------------------------------------------------------------
@respx.mock
async def test_fetch_github_signal_happy_path_with_link_header(github_repo_payload):
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(
        return_value=httpx.Response(200, json=github_repo_payload)
    )
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests/commits").mock(
        return_value=httpx.Response(
            200,
            json=[{"sha": "abc"}],
            headers={"Link": '<https://api.github.com/repositories/123/commits?per_page=1&page=6484>; rel="last"'},
        )
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_github_signal("psf", "requests", client)

    assert result["available"] is True
    assert result["stars"] == 58000
    assert result["owner_type"] == "Organization"
    assert result["commit_count"] == 6484
    assert result["commit_count_reliable"] is True


@respx.mock
async def test_fetch_github_signal_single_page_no_link_header(github_new_personal_repo_payload):
    respx.get(f"{GITHUB_API_BASE}/repos/new/repo").mock(
        return_value=httpx.Response(200, json=github_new_personal_repo_payload)
    )
    respx.get(f"{GITHUB_API_BASE}/repos/new/repo/commits").mock(
        return_value=httpx.Response(200, json=[{"sha": "only-one"}])
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_github_signal("new", "repo", client)

    assert result["commit_count"] == 1
    assert result["commit_count_reliable"] is True


@respx.mock
async def test_fetch_github_signal_not_found():
    respx.get(f"{GITHUB_API_BASE}/repos/nobody/nothing").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        result = await fetch_github_signal("nobody", "nothing", client)
    assert result == {"available": False, "reason": "not_found"}


@respx.mock
async def test_fetch_github_signal_rate_limited_403():
    respx.get(f"{GITHUB_API_BASE}/repos/owner/repo").mock(return_value=httpx.Response(403))
    async with httpx.AsyncClient() as client:
        result = await fetch_github_signal("owner", "repo", client)
    assert result == {"available": False, "reason": "rate_limited"}


@respx.mock
async def test_fetch_github_signal_rate_limited_429():
    respx.get(f"{GITHUB_API_BASE}/repos/owner/repo").mock(return_value=httpx.Response(429))
    async with httpx.AsyncClient() as client:
        result = await fetch_github_signal("owner", "repo", client)
    assert result == {"available": False, "reason": "rate_limited"}


@respx.mock
async def test_fetch_github_signal_timeout():
    respx.get(f"{GITHUB_API_BASE}/repos/owner/repo").mock(side_effect=httpx.TimeoutException("timed out"))
    async with httpx.AsyncClient() as client:
        result = await fetch_github_signal("owner", "repo", client)
    assert result == {"available": False, "reason": "request_error"}


@respx.mock
async def test_fetch_github_signal_uses_token_when_present(monkeypatch, github_repo_payload):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-123")
    repo_route = respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(
        return_value=httpx.Response(200, json=github_repo_payload)
    )
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests/commits").mock(
        return_value=httpx.Response(200, json=[])
    )
    async with httpx.AsyncClient() as client:
        await fetch_github_signal("psf", "requests", client)

    sent_request = repo_route.calls.last.request
    assert sent_request.headers["Authorization"] == "Bearer test-token-123"


@respx.mock
async def test_fetch_github_signal_skips_commits_call_when_rate_limit_exhausted(github_repo_payload):
    commits_route = respx.get(f"{GITHUB_API_BASE}/repos/psf/requests/commits").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(
        return_value=httpx.Response(200, json=github_repo_payload, headers={"X-RateLimit-Remaining": "0"})
    )
    async with httpx.AsyncClient() as client:
        result = await fetch_github_signal("psf", "requests", client)

    assert commits_route.call_count == 0
    assert result["commit_count_reliable"] is False


@pytest.fixture(autouse=False)
def reset_token_backoff():
    import main
    main._github_token_rejected_until = 0.0
    yield
    main._github_token_rejected_until = 0.0


@respx.mock
async def test_fetch_github_signal_follows_repo_redirect(github_repo_payload):
    # Renamed/transferred repos answer 301 -> /repositories/<id>.
    respx.get(f"{GITHUB_API_BASE}/repos/old/name").mock(
        return_value=httpx.Response(301, headers={"Location": f"{GITHUB_API_BASE}/repositories/123"})
    )
    respx.get(f"{GITHUB_API_BASE}/repositories/123").mock(return_value=httpx.Response(200, json=github_repo_payload))
    respx.get(f"{GITHUB_API_BASE}/repos/old/name/commits").mock(return_value=httpx.Response(200, json=[]))
    async with httpx.AsyncClient() as client:
        result = await fetch_github_signal("old", "name", client)
    assert result["available"] is True and result["stars"] == github_repo_payload["stargazers_count"]


@respx.mock
async def test_rejected_token_falls_back_to_unauthenticated_and_backs_off(monkeypatch, github_repo_payload, reset_token_backoff, caplog):
    import logging
    monkeypatch.setenv("GITHUB_TOKEN", "revoked-token")

    def responder(request):
        if request.headers.get("Authorization"):
            return httpx.Response(401, json={"message": "Bad credentials"})
        return httpx.Response(200, json=github_repo_payload)

    repo_route = respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(side_effect=responder)
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests/commits").mock(return_value=httpx.Response(200, json=[]))
    with caplog.at_level(logging.ERROR, logger="slopscan"):
        async with httpx.AsyncClient() as client:
            first = await fetch_github_signal("psf", "requests", client)
            second = await fetch_github_signal("psf", "requests", client)

    assert first["available"] is True and second["available"] is True
    assert "GITHUB_TOKEN was rejected" in caplog.text
    # call 1: authed (401) then unauthed retry; call 2 (inside the backoff window): unauthed only
    sent_auth = [bool(c.request.headers.get("Authorization")) for c in repo_route.calls]
    assert sent_auth == [True, False, False]


@respx.mock
async def test_valid_token_is_unaffected_by_backoff_logic(monkeypatch, github_repo_payload, reset_token_backoff):
    monkeypatch.setenv("GITHUB_TOKEN", "good-token")
    repo_route = respx.get(f"{GITHUB_API_BASE}/repos/psf/requests").mock(return_value=httpx.Response(200, json=github_repo_payload))
    respx.get(f"{GITHUB_API_BASE}/repos/psf/requests/commits").mock(return_value=httpx.Response(200, json=[]))
    async with httpx.AsyncClient() as client:
        await fetch_github_signal("psf", "requests", client)
        await fetch_github_signal("psf", "requests", client)
    assert [bool(c.request.headers.get("Authorization")) for c in repo_route.calls] == [True, True]
