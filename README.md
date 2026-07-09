# SlopScan 🔍

**Package hallucination detection API** — a lightweight micro-service that scores
AI-suggested packages for trustworthiness before they get installed.

Part of the [Sentinel-Proxy AI Firewall](https://sentinel-proxy.skyblue-soft.com) ecosystem by Skyblue-Soft.

---

## The Problem

LLMs hallucinate package names. ~20% of AI-generated code references packages
that don't exist. Attackers pre-register those names on PyPI/npm with malicious
payloads — an attack called **slopsquatting**. The worst part: 43% of hallucinated
names are *consistent* across runs, making them systematically targetable.

SlopScan sits in your agent/proxy pipeline and validates packages *before* they
are installed.

---

## Quickstart

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8765 --reload
```

API docs available at `http://localhost:8765/docs`

---

## Endpoints

### Single package check
```
GET /check/{ecosystem}/{package}
```
```bash
curl http://localhost:8765/check/pypi/requests
curl http://localhost:8765/check/npm/@scope/some-package
```

**Response:**
```json
{
  "package": "requests",
  "ecosystem": "pypi",
  "found": true,
  "trust_score": 97,
  "risk": "SAFE",
  "flags": [],
  "metadata": {
    "name": "requests",
    "version": "2.32.3",
    "age_days": 5200,
    "version_count": 48,
    "author": "Kenneth Reitz",
    ...
  },
  "cross_ecosystem_hit": false,
  "cached": false
}
```

Risk levels: `SAFE` (≥75) | `CAUTION` (≥50) | `SUSPICIOUS` (≥25) | `DANGEROUS` (<25)

---

### Batch check (up to 20 packages)
```
POST /check/batch
```
```bash
curl -X POST http://localhost:8765/check/batch \
  -H "Content-Type: application/json" \
  -d '{
    "packages": [
      {"ecosystem": "pypi", "name": "requests"},
      {"ecosystem": "npm",  "name": "lodash"},
      {"ecosystem": "pypi", "name": "starlette-reverse-proxy"}
    ]
  }'
```

**Response includes a summary:**
```json
{
  "results": [...],
  "summary": {
    "total": 3,
    "safe": 2,
    "caution": 0,
    "suspicious": 0,
    "dangerous": 1
  }
}
```

---

## Trust Score Breakdown

| Signal              | Weight | Notes                                          |
|---------------------|--------|------------------------------------------------|
| Package age (days)  | 25%    | <7 days = near-zero score                      |
| Download count      | 20%    | Proxy for real-world usage                     |
| Version count       | 15%    | 1 release = no maintenance history             |
| Maintainer age      | 10%    | Placeholder; PyPI/npm auth required for prod   |
| Cross-ecosystem hit | 15%    | Real npm package suggested for Python? Red flag.|
| GitHub repo signal  | 15%    | Repo age, last-push recency, commit count, stars, org vs. personal ownership |

If a package doesn't link a discoverable GitHub repo (or the GitHub API call fails/rate-limits), the GitHub signal's weight is **redistributed proportionally** across the other signals rather than being dropped or scored as 0 — packages aren't penalized just for not hosting on GitHub.

---

## Configuration

| Env var        | Required | Notes                                                                 |
|-----------------|----------|------------------------------------------------------------------------|
| `GITHUB_TOKEN`  | No       | Raises the GitHub API rate limit from 60/hr (unauthenticated) to 5000/hr. Without it, the GitHub signal still works but may degrade to "unavailable" sooner under load. |

---

## Caching

Results are cached in-memory: 24 hours for successful lookups (`CACHE_TTL`), 10 minutes for not-found/error results (`CACHE_TTL_ERROR`) — both configurable in `main.py`.

```bash
# Cache stats
GET /cache/stats

# Clear cache
DELETE /cache
```

---

## Sentinel Integration

SlopScan is designed to be queried by [Sentinel](https://sentinel-proxy.skyblue-soft.com)
at response-time, extracting package names from LLM output before they reach agentic
install pipelines. Wire it in as a Sentinel detection layer:

```python
# In your Sentinel response handler
packages = extract_packages_from_llm_response(response_text)
for pkg in packages:
    result = await slopscan_client.check(pkg.ecosystem, pkg.name)
    if result["risk"] in ("SUSPICIOUS", "DANGEROUS"):
        sentinel.flag(response, reason=f"Slopsquatting risk: {pkg.name}", details=result)
```

---

## Roadmap

- [ ] Tier 3: Hallucination fingerprint database (known bad names per model)
- [ ] Tier 4 enhancement: Full cross-ecosystem scoring (currently boolean flag)
- [ ] Real download counts via pypistats.org + npm download API
- [ ] Real maintainer account age via PyPI/npm authenticated APIs  
- [x] GitHub signal integration (stars, last commit, org ownership)
- [ ] Redis cache backend for multi-instance deployments
- [ ] Docker image
- [ ] Webhook/alert mode for continuous registry monitoring

---

## Contributing

This is an early-stage open-source project. PRs welcome, especially for:
- Additional ecosystems (RubyGems, crates.io, NuGet)
- Hallucination fingerprint dataset generation scripts
- Real download count integrations
- Docker + k8s deployment configs

---

## License

Apache 2.0 — use freely, contribute back if you can, mention Skyblue-Soft if youuse in your product.

Built with ❤️ by [Skyblue-Soft](https://skyblue-soft.com)
