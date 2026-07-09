import pytest


@pytest.fixture
def pypi_payload():
    """Shaped like the real PyPI JSON API response for a well-established package."""
    return {
        "info": {
            "name": "requests",
            "version": "2.32.3",
            "author": None,
            "maintainer": None,
            "summary": "Python HTTP for Humans.",
            "home_page": None,
            "license": "Apache-2.0",
            "requires_python": ">=3.8",
            "project_urls": {
                "Documentation": "https://requests.readthedocs.io",
                "Source": "https://github.com/psf/requests",
            },
            "downloads": {"last_month": -1},
        },
        "releases": {
            "2.32.3": [
                {"upload_time_iso_8601": "2024-05-29T15:37:24.567890Z"},
            ],
            "2.32.2": [
                {"upload_time_iso_8601": "2024-05-21T12:00:00.000000Z"},
            ],
            "0.2.0": [
                {"upload_time_iso_8601": "2011-02-14T00:00:00.000000Z"},
            ],
        },
    }


@pytest.fixture
def npm_payload_dict_repo():
    """npm registry payload with `repository` as a dict (the common shape)."""
    return {
        "name": "lodash",
        "time": {
            "created": "2012-04-19T14:38:41.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "4.17.21": "2021-02-20T00:00:00.000Z",
            "4.17.20": "2020-08-13T00:00:00.000Z",
        },
        "dist-tags": {"latest": "4.17.21"},
        "author": {"name": "John-David Dalton"},
        "description": "Lodash modular utilities.",
        "homepage": "https://lodash.com/",
        "license": "MIT",
        "repository": {"type": "git", "url": "git+https://github.com/lodash/lodash.git"},
    }


@pytest.fixture
def npm_payload_string_repo(npm_payload_dict_repo):
    """Same payload but with `repository` as a bare string (also seen in the wild)."""
    payload = dict(npm_payload_dict_repo)
    payload["repository"] = "github:lodash/lodash"
    return payload


@pytest.fixture
def github_repo_payload():
    return {
        "stargazers_count": 58000,
        "created_at": "2012-04-06T00:00:00Z",
        "pushed_at": "2024-06-01T00:00:00Z",
        "owner": {"type": "Organization"},
    }


@pytest.fixture
def github_new_personal_repo_payload():
    return {
        "stargazers_count": 0,
        "created_at": "2024-06-01T00:00:00Z",
        "pushed_at": "2024-06-02T00:00:00Z",
        "owner": {"type": "User"},
    }
