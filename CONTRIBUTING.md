# Contributing to SlopScan

First off — thanks for being here. SlopScan exists because slopsquatting is a real,
active threat and the tooling to fight it is still catching up. Every contribution,
whether it's a bug report, a new ecosystem fetcher, or a typo fix, makes the
package ecosystem a little safer for everyone.

---

## Ways to Contribute

### 🐛 Bug Reports
Found something broken? Open an issue with:
- What you ran
- What you expected
- What actually happened
- Your Python version and OS

### 💡 Feature Requests
Have an idea? Open an issue tagged `enhancement`. Check the roadmap below first
to see if it's already planned — if it is, a 👍 on the issue helps prioritize.

### 🔀 Pull Requests
All PRs welcome. Small focused changes merge faster than large sweeping ones.
If you're planning something significant, open an issue first so we can align
before you invest the time.

---

## Roadmap — Good First Issues

These are scoped, well-defined contributions that don't require deep knowledge
of the codebase. Perfect starting points:

### Easy
- **Fix PyPI author field fallback** — the PyPI JSON API no longer reliably
  returns `author` for packages that migrated to the new metadata format.
  Fallback chain: `author` → `maintainer` → `project_urls` → `""`. See `fetch_pypi()` in `main.py`.
- **Real npm download counts** — replace the placeholder estimate in `fetch_npm()`
  with a call to `https://api.npmjs.org/downloads/point/last-month/{package}`
- **Real PyPI download counts** — replace the placeholder in `fetch_pypi()` with
  a call to `https://pypistats.org/api/packages/{package}/recent`
- **Docker image** — Dockerfile is already there, just needs a CI workflow to
  build and push to Docker Hub on tag

### Medium
- **GitHub signal integration** — add optional GitHub metadata to the trust score:
  stars, last commit date, organization ownership. Hard signals that legitimate
  packages have and squatters rarely do. `GITHUB_TOKEN` env var for rate limits.
- **Redis cache backend** — swap the in-memory `_cache` dict for an optional Redis
  backend, configurable via `REDIS_URL` env var. Fall back to in-memory if not set.
- **crates.io ecosystem** — add `fetch_crates()` hitting
  `https://crates.io/api/v1/crates/{package}`. Follow the same fetcher pattern
  as `fetch_pypi()` and `fetch_npm()`. Add `"cargo"` as a valid ecosystem value.
- **RubyGems ecosystem** — `https://rubygems.org/api/v1/gems/{package}.json`
- **NuGet ecosystem** — `https://api.nuget.org/v3/registration5/{package}/index.json`

### Harder
- **Hallucination fingerprint database** — systematically prompt popular models
  with common developer questions, collect package names that appear consistently
  across runs (the 43% repeatability stat is your friend), and build a known-bad
  blocklist. This is the Tier 3 detection layer and probably the highest-value
  contribution possible.
- **Maintainer account age** — PyPI and npm both expose publisher account creation
  dates via authenticated APIs. A brand-new maintainer account is a strong signal.
  Needs API key handling and a contribution to the scoring engine.

---

## Development Setup

```bash
git clone https://github.com/c0ri/SlopScan.git
cd SlopScan
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8765
```

API docs at `http://localhost:8765/docs` — FastAPI generates these automatically.

---

## Code Style

- Standard Python — no framework opinions beyond FastAPI and httpx
- Type hints appreciated but not required for first contributions
- Keep fetcher functions consistent with the existing `fetch_pypi()` / `fetch_npm()` pattern
- New ecosystems go in their own `fetch_*()` function — don't extend existing ones
- Cache keys follow the pattern `{ecosystem}:{package_name_lowercased}`

---

## Adding a New Ecosystem

The pattern is intentionally simple. To add crates.io as an example:

1. Write `fetch_crates(package, client)` following the `fetch_pypi` pattern —
   return a dict with `found`, `age_days`, `version_count`, `downloads_estimate`, `author`, etc.
2. Add `"cargo"` to the ecosystem validation check in both route handlers
3. Wire the cross-ecosystem check in `score_package()` — decide which ecosystem
   crates.io should cross-check against (npm is a reasonable default)
4. Add a row to the ecosystem table in `README.md`

That's it. No changes to the scoring engine needed.

---

## Questions?

Open an issue and tag it `question`. Or find Cori at
[@coridev](https://dev.to/coridev) on dev.to or via [Skyblue](https://skyblue-soft.com).

---

Built with ❤️ by [Skyblue](https://skyblue-soft.com) · Apache 2.0 License
