"""
SlopScan — Package Hallucination Detection API
A Sentinel micro-service for validating AI-suggested packages against PyPI and npm.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import httpx
import time
import asyncio
from datetime import datetime, timezone

app = FastAPI(
    title="SlopScan",
    description="Package trust scoring API — detects hallucinated and suspicious packages from AI output.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Simple in-memory cache  {cache_key: (result_dict, expires_at_unix)}
# ---------------------------------------------------------------------------
_cache: dict[str, tuple[dict, float]] = {}
CACHE_TTL = 86400  # 24 hours


def _cache_get(key: str) -> Optional[dict]:
    entry = _cache.get(key)
    if entry and entry[1] > time.time():
        return entry[0]
    _cache.pop(key, None)
    return None


def _cache_set(key: str, value: dict) -> None:
    _cache[key] = (value, time.time() + CACHE_TTL)


# ---------------------------------------------------------------------------
# Scoring weights  (must sum to 100)
# ---------------------------------------------------------------------------
WEIGHTS = {
    "age_days":        30,   # How old is the package? New = suspicious.
    "download_count":  25,   # Proxy for real-world usage.
    "version_count":   15,   # Active maintenance signal.
    "maintainer_age":  15,   # Is the publisher account also brand new?
    "cross_ecosystem": 15,   # Does the name exist in the *other* ecosystem?
}

AGE_THRESHOLDS   = [(7, 0), (30, 20), (90, 45), (365, 70), (9999, 100)]
DL_THRESHOLDS    = [(100, 0), (1_000, 20), (10_000, 50), (100_000, 75), (1_000_000, 100)]
VER_THRESHOLDS   = [(1, 10), (3, 30), (5, 55), (10, 80), (9999, 100)]


def _score_threshold(value: int, thresholds: list[tuple]) -> int:
    for limit, score in thresholds:
        if value <= limit:
            return score
    return 100


def _risk_label(score: int) -> str:
    if score >= 75:
        return "SAFE"
    if score >= 50:
        return "CAUTION"
    if score >= 25:
        return "SUSPICIOUS"
    return "DANGEROUS"


# ---------------------------------------------------------------------------
# PyPI fetcher
# ---------------------------------------------------------------------------
async def fetch_pypi(package: str, client: httpx.AsyncClient) -> dict:
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        r = await client.get(url, timeout=8.0)
    except httpx.TimeoutException:
        return {"error": "timeout"}

    if r.status_code == 404:
        return {"error": "not_found"}
    if r.status_code != 200:
        return {"error": f"http_{r.status_code}"}

    data = r.json()
    info = data.get("info", {})
    releases = data.get("releases", {})

    # Earliest upload date across all releases
    earliest = None
    for files in releases.values():
        for f in files:
            upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
            if upload_time:
                try:
                    dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                    if earliest is None or dt < earliest:
                        earliest = dt
                except ValueError:
                    pass

    age_days = 0
    if earliest:
        age_days = (datetime.now(timezone.utc) - earliest).days

    # Download stats — PyPI doesn't expose totals in the JSON API directly,
    # so we sum the last-month counts from the most recent release files as proxy.
    # (For production: wire up pypistats.org/api/packages/{pkg}/recent)
    total_downloads = info.get("downloads", {}).get("last_month", -1)
    if total_downloads == -1:
        # Estimate from number of releases × 500 as a floor; flag for real stats
        total_downloads = len(releases) * 500

    version_count = len(releases)
    author = info.get("author") or info.get("maintainer") or ""

    return {
        "found": True,
        "ecosystem": "pypi",
        "name": info.get("name", package),
        "version": info.get("version", "unknown"),
        "age_days": age_days,
        "version_count": version_count,
        "downloads_estimate": total_downloads,
        "author": author,
        "summary": info.get("summary", ""),
        "home_page": info.get("home_page") or info.get("project_url") or "",
        "license": info.get("license", ""),
        "requires_python": info.get("requires_python", ""),
    }


# ---------------------------------------------------------------------------
# npm fetcher
# ---------------------------------------------------------------------------
async def fetch_npm(package: str, client: httpx.AsyncClient) -> dict:
    url = f"https://registry.npmjs.org/{package}"
    try:
        r = await client.get(url, timeout=8.0)
    except httpx.TimeoutException:
        return {"error": "timeout"}

    if r.status_code == 404:
        return {"error": "not_found"}
    if r.status_code != 200:
        return {"error": f"http_{r.status_code}"}

    data = r.json()
    time_data = data.get("time", {})

    created_str = time_data.get("created")
    age_days = 0
    if created_str:
        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created).days
        except ValueError:
            pass

    versions = [k for k in time_data if k not in ("created", "modified")]
    version_count = len(versions)
    latest = data.get("dist-tags", {}).get("latest", "unknown")
    author_info = data.get("author", {})
    author = author_info.get("name", "") if isinstance(author_info, dict) else str(author_info)

    return {
        "found": True,
        "ecosystem": "npm",
        "name": data.get("name", package),
        "version": latest,
        "age_days": age_days,
        "version_count": version_count,
        "downloads_estimate": version_count * 500,   # placeholder; use npm download counts API for prod
        "author": author,
        "summary": data.get("description", ""),
        "home_page": data.get("homepage", ""),
        "license": data.get("license", ""),
        "requires_python": None,
    }


# ---------------------------------------------------------------------------
# Trust scoring engine
# ---------------------------------------------------------------------------
async def score_package(ecosystem: str, package: str, client: httpx.AsyncClient) -> dict:
    cache_key = f"{ecosystem}:{package.lower()}"
    cached = _cache_get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    # Fetch primary ecosystem
    if ecosystem == "pypi":
        primary = await fetch_pypi(package, client)
        # Tier 4: check if the name exists in npm (cross-ecosystem confusion)
        cross = await fetch_npm(package, client)
    else:
        primary = await fetch_npm(package, client)
        cross = await fetch_pypi(package, client)

    if "error" in primary:
        result = {
            "package": package,
            "ecosystem": ecosystem,
            "found": False,
            "error": primary["error"],
            "trust_score": 0,
            "risk": "DANGEROUS",
            "flags": ["Package does not exist in registry — likely hallucinated"],
            "cached": False,
        }
        _cache_set(cache_key, result)
        return result

    flags = []
    component_scores = {}

    # Age score
    age_score = _score_threshold(primary["age_days"], AGE_THRESHOLDS)
    component_scores["age_days"] = age_score
    if primary["age_days"] < 14:
        flags.append(f"Very new package ({primary['age_days']} days old)")
    elif primary["age_days"] < 60:
        flags.append(f"Recent package ({primary['age_days']} days old) — verify carefully")

    # Download score
    dl_score = _score_threshold(primary["downloads_estimate"], DL_THRESHOLDS)
    component_scores["download_count"] = dl_score
    if primary["downloads_estimate"] < 500:
        flags.append("Very low download count")

    # Version count score
    ver_score = _score_threshold(primary["version_count"], VER_THRESHOLDS)
    component_scores["version_count"] = ver_score
    if primary["version_count"] == 1:
        flags.append("Only one release version — no maintenance history")

    # Maintainer age — we don't have direct account-age data from public APIs without auth,
    # so we use package age as proxy for now (flag for enhancement)
    component_scores["maintainer_age"] = age_score  # same signal, placeholder

    # Cross-ecosystem check (Tier 4)
    cross_exists = cross.get("found", False)
    cross_score = 0 if cross_exists else 100
    component_scores["cross_ecosystem"] = cross_score
    if cross_exists:
        other = "npm" if ecosystem == "pypi" else "pypi"
        flags.append(
            f"Name also exists in {other} — possible cross-ecosystem confusion attack"
        )

    # Weighted trust score
    trust_score = sum(
        component_scores[k] * (WEIGHTS[k] / 100)
        for k in WEIGHTS
    )
    trust_score = round(trust_score)

    if not primary.get("author"):
        flags.append("No author/maintainer info")
        trust_score = max(0, trust_score - 10)

    if not primary.get("home_page"):
        flags.append("No homepage or repository link")

    result = {
        "package": package,
        "ecosystem": ecosystem,
        "found": True,
        "trust_score": trust_score,
        "risk": _risk_label(trust_score),
        "flags": flags,
        "metadata": {
            "name": primary["name"],
            "version": primary["version"],
            "age_days": primary["age_days"],
            "version_count": primary["version_count"],
            "downloads_estimate": primary["downloads_estimate"],
            "author": primary["author"],
            "summary": primary["summary"],
            "home_page": primary["home_page"],
            "license": primary["license"],
        },
        "component_scores": component_scores,
        "cross_ecosystem_hit": cross_exists,
        "cached": False,
    }

    _cache_set(cache_key, result)
    return result


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class BatchRequest(BaseModel):
    packages: list[dict]   # [{"ecosystem": "pypi", "name": "requests"}, ...]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "service": "slopscan", "version": "0.1.0"}


@app.get("/check/{ecosystem}/{package:path}")
async def check_package(ecosystem: str, package: str):
    """
    Check a single package.

    ecosystem: pypi | npm
    package:   exact package name (scoped npm names supported, e.g. @scope/pkg)
    """
    ecosystem = ecosystem.lower()
    if ecosystem not in ("pypi", "npm"):
        raise HTTPException(status_code=400, detail="ecosystem must be 'pypi' or 'npm'")

    async with httpx.AsyncClient() as client:
        return await score_package(ecosystem, package, client)


@app.post("/check/batch")
async def check_batch(req: BatchRequest):
    """
    Check multiple packages in one call.
    Body: { "packages": [{"ecosystem": "pypi", "name": "requests"}, ...] }
    Max 20 per request.
    """
    if len(req.packages) > 20:
        raise HTTPException(status_code=400, detail="Max 20 packages per batch request")

    async with httpx.AsyncClient() as client:
        tasks = [
            score_package(p.get("ecosystem", "pypi"), p["name"], client)
            for p in req.packages
            if p.get("name")
        ]
        results = await asyncio.gather(*tasks)

    return {
        "results": list(results),
        "summary": {
            "total": len(results),
            "safe":       sum(1 for r in results if r.get("risk") == "SAFE"),
            "caution":    sum(1 for r in results if r.get("risk") == "CAUTION"),
            "suspicious": sum(1 for r in results if r.get("risk") == "SUSPICIOUS"),
            "dangerous":  sum(1 for r in results if r.get("risk") == "DANGEROUS"),
        },
    }


@app.get("/cache/stats")
async def cache_stats():
    now = time.time()
    live = sum(1 for _, exp in _cache.values() if exp > now)
    return {"cached_entries": live, "total_stored": len(_cache)}


@app.delete("/cache")
async def clear_cache():
    _cache.clear()
    return {"cleared": True}
