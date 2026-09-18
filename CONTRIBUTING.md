# Contributing to SpooNMAP

Thanks for your interest. SpooNMAP orchestrates masscan and nmap, so most useful
contributions are fixes to how a scan phase drives one of those tools, new or
corrected NSE scripts under `nse/`, better findings output, or resume/coverage
correctness.

Please read the three short sections below before you start. One is about
engagement data, which matters more here than in most projects. One is about
which branch to target, which is easy to get wrong. One is about regression
tests, which are not optional here.

## Never include real engagement data

SpooNMAP is run from jumpboxes inside client networks on authorized penetration
tests, so the files it reads and writes describe somebody else's infrastructure.
**Do not put any of it in an issue, a pull request, a commit, a test fixture, or
a screenshot.** That includes client IP ranges, hostnames, resolved DNS names,
TLS certificate subjects, service banners, masscan and nmap XML output,
`findings.*`, and anything naming an organization.

When you need example data, invent it. Use documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or RFC1918 addresses and
made-up hostnames, exactly as the existing tests do. When you need to describe a
result, report aggregates that cannot be reversed.

`.gitignore` already covers what SpooNMAP writes: `config.json`,
`discovery/`, `live_hosts/`, `masscan_results/`, `nmap_results/`,
`nse_results/`, `all_live_hosts.txt`, `spoonmap_output.*`, `findings.*`,
`resume.cfg` and more. Do not weaken those patterns to commit something, and do
not `git add -A` past a file that shows up untracked because a local scan
produced it.

`tests/test_nse_integration.py` binds real local ports and shells out to real
`nmap` against `127.0.0.1`. Keep it that way — no test in this repo may send a
packet to an address it does not own.

## Target `dev`, not `main`

`main` is the default branch, so GitHub will preselect it — **change the base to
`dev`.** `main` holds the last released state and receives work only through a
batch integration merge from `dev`. A pull request landing on `main` directly
breaks that and creates cleanup for the maintainers.

```bash
git clone https://github.com/<you>/spoonmap
cd spoonmap
git checkout -b my-change origin/dev
# ... work ...
git push -u origin my-change     # then open a PR with base: dev
```

Branch names follow a `type/short-description` pattern matching the prefixes
already on `origin`: `feat/`, `fix/`, `docs/`, `test/`, `chore/`, `ci/`.

One exception goes straight to `main`: a security fix that must ship
immediately. Say so in the PR body.

`CLAUDE.md` describes the same flow from the maintainer side under "Release
Versioning", and it is worth reading if you want the reasoning. The mechanic you
do not need to do anything about, but should know exists: maintainers integrate
`dev` into `main` with a **merge or a fast-forward, never a squash**. CI derives
every release version from the commits themselves, and a squash merge collapses
already-released commits into one that no prior tag can reach, which silently
corrupts every version computed afterward.

## Every bug fix needs a regression test

**A pull request that fixes a bug must add a test that fails before your change
and passes after it.** This is the one rule reviewers will not waive. Say in the
PR body which test it is, and confirm you watched it fail on the unfixed code —
a test written after the fix that has never been seen red is not evidence the
fix does anything.

This matters more here than the phrase usually implies, because almost every bug
this project has shipped failed *quietly*. A resume gate that accepts a stale
cache, a coverage record written on a killed scan, a `task_done()` called twice,
a masscan sweep aimed at the whole range instead of the live hosts — none of
them raised, none of them printed anything wrong, and each produced a scan that
reported itself complete while missing hosts. An operator cannot see that. The
test suite is the only thing that can, so assert on the *specific* wrong
behaviour, not merely that the function returns.

Practical guidance:

- Name the test after the behaviour, not the function, and put the reasoning in
  the docstring. Match what is already in `tests/test_spoonmap.py` — the
  docstrings there explain why the old behaviour was wrong, which is the part a
  future reader needs.
- Prove the failure mode, not the code path. If the bug under-scanned, assert on
  the target set actually handed to masscan or nmap. If it lost results, assert
  the retained host is still present in the written file.
- New features need tests too, including the failure and interrupt paths.
  `KeyboardInterrupt` is a `BaseException`, and getting that wrong has already
  cost this repo a correctness bug.
- If a bug is real but you are not fixing it in this PR, open an issue rather
  than leaving it undocumented.

Coverage is floored at 95% by pytest's `addopts`, so every job inherits it. Do
not lower the floor to land a change.

## Setting up

Requires **Python 3.8 or newer**, [uv](https://docs.astral.sh/uv/), and both
`masscan` and `nmap` installed as system binaries. `spoonmap.py` itself is
dependency-free stdlib; everything in `uv.lock` is test tooling.

```bash
git clone https://github.com/<you>/spoonmap
cd spoonmap
uv sync
```

`uv.lock` is deliberately resolved for Python 3.10+ only, so it can hold a
pytest patched for CVE-2025-71176. `requires-python` stays `>=3.8` because the
tool itself runs there — if you are developing on 3.8 or 3.9, resolve the test
tooling outside the project the way CI's `test-legacy` job does:

```bash
uv run --isolated --no-project --python 3.8 \
  --with pytest --with pytest-cov --with pyyaml --with packaging \
  pytest tests/ -v -rs
```

## Before you open a pull request

Run everything below. These are the same gates CI runs, so running them locally
is faster than waiting on a red check.

```bash
# Tests (the 95% coverage floor comes from pyproject.toml's addopts)
uv run --frozen pytest -rs tests/

# Lint
uv run --frozen ruff check spoonmap.py tests/ tools/

# Security
uv run --frozen bandit -r spoonmap.py -c pyproject.toml -b .bandit-baseline.json

# Lock file freshness (only if you touched pyproject.toml)
uv lock --check

# Workflow files (only if you touched .github/workflows/)
uvx --from "actionlint-py==1.7.12.24" actionlint
uvx zizmor==1.29.0 --persona=regular .github/workflows/
```

Notes on the gates:

- **`ruff format` is deliberately not adopted.** Do not run it. Reformatting the
  module and the test file would bury every future diff.
- **`.bandit-baseline.json` is committed**, so only a *new* finding fails the
  build. Do not add inline `# nosec` suppressions — if your change introduces a
  finding that is genuinely fine, regenerate the baseline deliberately and
  justify the addition in the commit message. The same goes for a type or lint
  error: fix it, do not suppress it.
- **Pass `-rs`.** Several NSE integration tests skip when the port they need is
  occupied or when you are not root, and a bare pass count hides a test that
  started skipping for the wrong reason. CI's `nse-root` job exists precisely
  because a skip is not a failure.
- Some NSE tests run only as root (the `-sU` path). You are not expected to run
  those locally; CI does.

## Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org/),
because the release version is derived from them by `tools/next_version.py`: any
`feat` in a batch moves the minor version, while `fix`, `docs`, `chore` and
friends move the patch. A `!` or a `BREAKING CHANGE:` footer counts as a
feature — the major version is only ever bumped by hand.

This makes your subject line load-bearing. **A feature typo'd as `fix:` ships as
a patch release**, and there is no file to correct it in afterward: versions are
tags cut by CI, not a string in the repository.

Keep commits atomic — one logical change each. Reference an issue with `(#NNN)`
at the end of the subject when one exists.

## Adding or changing an NSE script

Scripts under `nse/` ship inside the built wheel and sdist, and the `build` CI
job asserts that both contain *exactly* the set of files in that directory —
not merely a superset. So a script you leave there mid-engagement would ship to
every install, and the build will tell you. Add only scripts intended for
release.

Bundled scripts that probe HTTP must send a `User-Agent` and must target
`host.targetname` rather than `host.ip`, reading
`stdnse.get_script_args('http.useragent')` first so the `scanner_profile`
setting reaches them. See the "Scanner Signature Reduction" section of
`CLAUDE.md` for why both are correctness requirements and not style points.

## Reporting a bug

Useful reports say what you ran, what happened, and what you expected — plus
your OS, your Python version, and the versions of `masscan` and `nmap`
(`masscan --version`, `nmap --version`). Include your `config.json` with the
target paths and any client-identifying values removed, and say which scan type
and `target_scan` you used.

If the bug involves a crash, the traceback is the most valuable thing you can
include. Read it for client hostnames and paths before you paste it.

If the bug is a scan that reported itself complete but missed something, say how
you know — that class of bug is the hardest to reproduce and the most important
to fix.

## Questions

Open an issue. If you are unsure whether an idea fits, asking first is welcome
and cheaper than building it.
