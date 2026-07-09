from main import (
    AGE_THRESHOLDS,
    GITHUB_SUBWEIGHTS,
    WEIGHTS,
    _author_from_project_urls,
    _extract_github_repo,
    _risk_label,
    _score_github_signal,
    _score_threshold,
    _weighted_score,
)


def test_weights_sum_to_100():
    assert sum(WEIGHTS.values()) == 100


def test_github_subweights_sum_to_100():
    assert sum(GITHUB_SUBWEIGHTS.values()) == 100


def test_score_threshold_boundaries():
    # AGE_THRESHOLDS = [(7, 0), (30, 20), (90, 45), (365, 70), (9999, 100)]
    assert _score_threshold(0, AGE_THRESHOLDS) == 0
    assert _score_threshold(7, AGE_THRESHOLDS) == 0
    assert _score_threshold(8, AGE_THRESHOLDS) == 20
    assert _score_threshold(30, AGE_THRESHOLDS) == 20
    assert _score_threshold(31, AGE_THRESHOLDS) == 45
    assert _score_threshold(365, AGE_THRESHOLDS) == 70
    assert _score_threshold(366, AGE_THRESHOLDS) == 100
    assert _score_threshold(999999, AGE_THRESHOLDS) == 100


def test_risk_label_boundaries():
    assert _risk_label(100) == "SAFE"
    assert _risk_label(75) == "SAFE"
    assert _risk_label(74) == "CAUTION"
    assert _risk_label(50) == "CAUTION"
    assert _risk_label(49) == "SUSPICIOUS"
    assert _risk_label(25) == "SUSPICIOUS"
    assert _risk_label(24) == "DANGEROUS"
    assert _risk_label(0) == "DANGEROUS"


def test_weighted_score_full_availability_matches_plain_average():
    scores = {"age_days": 100, "download_count": 0, "version_count": 50,
              "maintainer_age": 100, "cross_ecosystem": 100, "github_signal": 0}
    expected = round(sum(scores[k] * WEIGHTS[k] / 100 for k in WEIGHTS))
    assert _weighted_score(scores, WEIGHTS) == expected


def test_weighted_score_redistributes_missing_signal():
    # Drop github_signal (weight 15) — remaining weights sum to 85 and each
    # signal's effective weight becomes weight * (100/85).
    scores = {"age_days": 100, "download_count": 0, "version_count": 50,
              "maintainer_age": 100, "cross_ecosystem": 100}
    available_total = 100 - WEIGHTS["github_signal"]
    expected = round(sum(scores[k] * WEIGHTS[k] for k in scores) / available_total)
    assert _weighted_score(scores, WEIGHTS) == expected
    # Sanity: this must differ from naively treating the missing signal as 0
    naive_zero = round(sum(scores.get(k, 0) * WEIGHTS[k] / 100 for k in WEIGHTS))
    assert _weighted_score(scores, WEIGHTS) >= naive_zero


def test_weighted_score_all_missing_returns_zero():
    assert _weighted_score({}, WEIGHTS) == 0


def test_score_github_signal_happy_path():
    gh = {
        "repo_age_days": 4000,
        "days_since_push": 10,
        "stars": 58000,
        "owner_type": "Organization",
        "commit_count": 6484,
        "commit_count_reliable": True,
    }
    score = _score_github_signal(gh)
    assert score >= 90  # old, active, popular, org-owned repo should score very high


def test_score_github_signal_new_personal_repo_scores_low():
    gh = {
        "repo_age_days": 1,
        "days_since_push": 1,
        "stars": 0,
        "owner_type": "User",
        "commit_count": 1,
        "commit_count_reliable": True,
    }
    # push_recency scores high here since the repo was just pushed to (true of any
    # brand-new repo) — repo_age/stars/commit_count/owner_type still drag it well
    # below a legitimate, established repo's score.
    score = _score_github_signal(gh)
    assert score <= 40


def test_score_github_signal_redistributes_when_commit_count_unreliable():
    gh_reliable = {
        "repo_age_days": 4000, "days_since_push": 10, "stars": 58000,
        "owner_type": "Organization", "commit_count": 0, "commit_count_reliable": False,
    }
    # commit_count key should be dropped and its weight redistributed, not scored as 0
    score = _score_github_signal(gh_reliable)
    assert score >= 90


def test_extract_github_repo_plain_https():
    assert _extract_github_repo(["https://github.com/psf/requests"]) == ("psf", "requests")


def test_extract_github_repo_git_plus_https_with_git_suffix():
    assert _extract_github_repo(["git+https://github.com/lodash/lodash.git"]) == ("lodash", "lodash")


def test_extract_github_repo_scp_style():
    assert _extract_github_repo(["git@github.com:lodash/lodash.git"]) == ("lodash", "lodash")


def test_extract_github_repo_git_protocol():
    assert _extract_github_repo(["git://github.com/lodash/lodash.git"]) == ("lodash", "lodash")


def test_extract_github_repo_trailing_path():
    assert _extract_github_repo(["https://github.com/psf/requests/issues"]) == ("psf", "requests")


def test_extract_github_repo_rejects_gist_lookalike():
    assert _extract_github_repo(["https://gist.github.com/someone/abc123"]) is None


def test_extract_github_repo_rejects_non_github_host():
    assert _extract_github_repo(["https://gitlab.com/owner/repo"]) is None


def test_extract_github_repo_empty_or_none_urls():
    assert _extract_github_repo([]) is None
    assert _extract_github_repo([None, "", "https://example.com"]) is None


def test_author_from_project_urls_with_github_source():
    project_urls = {"Documentation": "https://requests.readthedocs.io",
                     "Source": "https://github.com/psf/requests"}
    assert _author_from_project_urls(project_urls) == "psf (inferred from GitHub)"


def test_author_from_project_urls_empty():
    assert _author_from_project_urls({}) == ""


def test_author_from_project_urls_no_github_link():
    assert _author_from_project_urls({"Homepage": "https://example.com"}) == ""
