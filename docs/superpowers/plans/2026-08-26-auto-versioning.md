# Auto-Versioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give SpooNMAP tag-driven release versioning — CI-gated tags cut automatically from conventional-commit content, a package version derived from git rather than a hand-maintained string, an operator-visible `--version`, and an update check that is off unless explicitly enabled.

**Architecture:** A pure policy module (`tools/next_version.py`) decides what the next tag is; two `workflow_run`-triggered workflows call it and push the tag it prints, one per channel (`nightly` cuts `vX.Y.ZrcN` candidates, `main` cuts the `vX.Y.Z` final plus a GitHub release). `hatch-vcs` reads the resulting tags to produce the package version, and `spoonmap.py` reads that version back out of installed distribution metadata.

**Tech Stack:** Python 3.8+ stdlib, hatchling + hatch-vcs, GitHub Actions, pytest, uv.

**Spec:** `docs/superpowers/specs/2026-08-26-auto-versioning-design.md` — read it before starting. Where this plan and the spec disagree, this plan wins: three spec claims were checked against reality while writing it and corrected (noted inline at Tasks 2, 3 and 5).

## Global Constraints

- **Working directory is the worktree `/tmp/spoonmap-auto-versioning`, branch `feat/auto-versioning`.** Do not edit `/Users/justinbollinger/projects/spoonmap` directly.
- **`spoonmap.py` stays dependency-free stdlib.** No `requests`, no `packaging`, no import of anything under `tools/`. The wheel ships `spoonmap.py` alone.
- **Python floor is 3.8** for `spoonmap.py`, `tools/`, and everything under `tests/`. The `test-legacy` CI job runs the whole suite on 3.8 and 3.9. That means no `tuple[int, int, int]` / `list[str]` / `X | None` evaluated at runtime — use `typing.Tuple`, `typing.List`, `typing.Optional`. Under `from __future__ import annotations`, function *annotations* are fine; a module-level type alias is not, because it is evaluated.
- **Test commands:** `uv run pytest tests/` for the suite; `uv run pytest tests/test_next_version.py -v` for one module. The 95% coverage floor lives in `pyproject.toml`'s `addopts` and applies to every run.
- **Lint/SAST:** `uv run --frozen ruff check spoonmap.py tests/ tools/` and `uv run --frozen bandit -r spoonmap.py -c pyproject.toml -b .bandit-baseline.json`.
- **No `# nosec`, no `# noqa`, no rule downgrades.** If bandit reports a new finding, regenerate `.bandit-baseline.json` deliberately and justify the addition in the commit message.
- **Conventional commits.** Subjects are `feat:`, `fix:`, `docs:`, `chore:`, `test:`. This is now load-bearing: `tools/next_version.py` reads these subjects to pick the bump.
- **Repo slug is `trustedsec/spoonmap`.** Default branch `main`, dev branch `nightly`.
- **No seed tag is pushed.** The repo has no tags and stays that way; the policy's zero baseline is intended.

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `tools/next_version.py` | create | The entire version policy. Pure functions plus a thin git boundary and a `--channel` CLI. Nothing else parses or increments a version. |
| `tests/test_next_version.py` | create | Unit tests for the policy. |
| `tests/test_release_versioning.py` | create | Guards the wiring that breaks silently: CI triggers, workflow steps, config coherence. |
| `.github/workflows/nightly-tag.yml` | create | RC tags on `nightly`. |
| `.github/workflows/auto-tag.yml` | create | Final tags + GitHub release on `main`. |
| `.github/workflows/release.yml` | create | Release for hand-pushed tags. |
| `.github/workflows/ci.yml` | modify | Add `nightly` to push triggers; `fetch-depth: 0` on `build`; extend ruff and legacy-test deps. |
| `pyproject.toml` | modify | hatch-vcs dynamic version; sdist includes `tools/`; dev group gains `pyyaml` + `packaging`. |
| `spoonmap.py` | modify | `_tool_version()`, `_check_for_updates()`, `_maybe_check_for_updates()`, `--version` / `--check-update` dispatch, `check_for_updates` config key. |
| `tests/test_spoonmap.py` | modify | Tests for the four functions above, including the inert-default network guard. |
| `config.json.sample` | modify | Document `check_for_updates`, explicitly `false`. |
| `README.md` | modify | Document the flags and the config key. |
| `CLAUDE.md` | modify | Document the release policy and its non-obvious constraints. |

---

### Task 1: The version policy module

**Files:**
- Create: `tools/next_version.py`
- Test: `tests/test_next_version.py`

**Interfaces:**
- Consumes: nothing.
- Produces, all importable as `from tools.next_version import ...`:
  - `parse_final(tag: str) -> Optional[Tuple[int, int, int]]`
  - `latest_final(tags: List[str]) -> Tuple[int, int, int]`
  - `has_feature(messages: List[str]) -> bool`
  - `target_version(base: Tuple[int, int, int], messages: List[str]) -> Optional[Tuple[int, int, int]]`
  - `next_rc_number(target: Tuple[int, int, int], tags: List[str]) -> int`
  - `format_version(version: Tuple[int, int, int]) -> str`
  - `compute(channel: str, tags: List[str], messages: List[str]) -> Optional[str]`
  - `git_tags(repo_dir: str) -> List[str]`
  - `commit_messages(repo_dir: str, base: Tuple[int, int, int]) -> List[str]`
  - `main(argv: Optional[List[str]] = None) -> int`
  - CLI: `python3 tools/next_version.py --channel {stable,nightly} [--repo-dir DIR]` prints the tag to create, or prints nothing, and exits 0 either way.

This module is a port of `/Users/justinbollinger/projects/hate_crack/tools/next_version.py`. Copy it rather than retyping it — the policy is subtle and transcription errors here are silent.

- [ ] **Step 1: Copy the module and its tests**

```bash
cd /tmp/spoonmap-auto-versioning
mkdir -p tools
cp /Users/justinbollinger/projects/hate_crack/tools/next_version.py tools/next_version.py
cp /Users/justinbollinger/projects/hate_crack/tests/test_next_version.py tests/test_next_version.py
```

- [ ] **Step 2: Run the tests to see where the copy stands**

Run: `uv run pytest tests/test_next_version.py -v`

Expected: PASS. If anything fails, fix it before continuing — you are looking at a policy bug, not a porting artifact.

- [ ] **Step 3: Make the module Python 3.8-safe**

In `tools/next_version.py`, the module-level alias is evaluated at import and fails on 3.8. Replace:

```python
Version = tuple[int, int, int]
```

with:

```python
from typing import List, Optional, Tuple

# Evaluated at import, so it cannot use PEP 585 builtin generics: the whole
# suite runs on 3.8 in the `test-legacy` CI job.
Version = Tuple[int, int, int]
```

placing the `typing` import with the other imports at the top. Then replace every `X | None` annotation with `Optional[X]` and every `list[str]` with `List[str]` throughout the file. `from __future__ import annotations` stays.

- [ ] **Step 4: Verify it imports on the actual floor**

Run:
```bash
uv run --isolated --no-project --python 3.8 python -c "import sys; sys.path.insert(0, '.'); import tools.next_version as n; print(n.compute('nightly', [], ['fix: x']))"
```
Expected: prints `v0.0.1rc1`. A `TypeError: 'type' object is not subscriptable` means a PEP 585 generic survived Step 3.

- [ ] **Step 5: Adapt the tests to SpooNMAP**

In `tests/test_next_version.py`: apply the same 3.8 fixes if any annotation in it uses builtin generics, and rewrite the module docstring so it describes SpooNMAP's branches (`nightly`, not `nightly-dev`) and does not reference hate_crack's two abandoned schemes, which never existed here. Keep every test — the policy is identical and the historical hazards it guards are real. Then append the two cases specific to starting from zero:

```python
def test_a_repository_with_no_tags_cuts_the_first_patch():
    """SpooNMAP starts from zero: no seed tag is pushed, deliberately."""
    assert compute("stable", [], ["fix: first fix"]) == "v0.0.1"


def test_a_first_batch_containing_a_feature_cuts_the_first_minor():
    """The whole history is one batch on the first run, so a single `feat`
    anywhere in it takes the first release to 0.1.0 rather than 0.0.1."""
    assert compute("nightly", [], ["fix: a", "feat: b", "docs: c"]) == "v0.1.0rc1"
```

- [ ] **Step 6: Run the adapted tests**

Run: `uv run pytest tests/test_next_version.py -v`
Expected: PASS, including the two new tests.

- [ ] **Step 7: Add `packaging` to the dev group**

`tests/test_next_version.py` imports `packaging.version.parse` to assert tag ordering against a real PEP 440 parser. Add it to `[dependency-groups].dev` in `pyproject.toml`:

```toml
    # Test-only. tests/test_next_version.py asserts candidate/release ordering
    # against a real PEP 440 parser rather than by eyeball, because two
    # different pre-release schemes have been got wrong before. Not a runtime
    # dependency: spoonmap.py is stdlib-only.
    "packaging>=24.0",
```

Then run `uv lock` (the `lint` CI job runs `uv lock --check` and fails on a stale lock).

- [ ] **Step 8: Lint and commit**

```bash
cd /tmp/spoonmap-auto-versioning
uv run --frozen ruff check spoonmap.py tests/ tools/
uv run pytest tests/test_next_version.py -v
git add tools/next_version.py tests/test_next_version.py pyproject.toml uv.lock
git commit -m "feat: add tools/next_version.py, the release version policy

Ported from hate_crack, where it replaced ~70 lines of \`cut -d.\` version
arithmetic duplicated across two workflow files. The policy lives in Python
so it can be unit-tested; nothing in YAML parses or increments a version.

Adapted for a 3.8 floor: the module-level Version alias is evaluated at
import, so PEP 585 builtin generics would break the test-legacy CI job."
```

---

### Task 2: Derive the package version from git tags

**Files:**
- Modify: `pyproject.toml` (build-system, `[project]`, sdist include, new `[tool.hatch.version]`)
- Modify: `.github/workflows/ci.yml` (`build` job checkout, ~line 363)

**Interfaces:**
- Consumes: nothing from Task 1 at runtime; the tags Task 3 pushes are what this reads.
- Produces: a distribution whose version comes from `git describe`. `importlib.metadata.version('spoonmap')` returns it once installed — Task 4 depends on that.

**Correction to the spec:** the spec says a shallow clone makes `uv build` *fail*. It does not. Verified against a real build: a depth-1 clone builds successfully and produces a silently **wrong** version (`0.0.post1.dev1` instead of `0.0.1.post1.dev1`), because the tag it should have described from was never fetched. `fetch-depth: 0` therefore guards against silent mis-versioning, which is worse than a crash, not against a build error. The spec's related worry about `uv build` building the wheel from the sdist (where there is no `.git`) is also unfounded — verified working, because hatch-vcs records the version in the sdist metadata.

- [ ] **Step 1: Switch the build to hatch-vcs**

In `pyproject.toml`, change the build backend requirements:

```toml
[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"
```

In `[project]`, delete `version = "0.1.0"` and add `dynamic`:

```toml
[project]
name = "spoonmap"
dynamic = ["version"]
description = "masscan + nmap orchestration wrapper for fast network scanning"
```

Add a new section (put it directly above `[tool.hatch.build.targets.wheel]`):

```toml
# The version is derived from git tags, not stored here. Tags are cut by
# .github/workflows/{auto,nightly}-tag.yml from tools/next_version.py, so a
# hand-maintained version string would only ever be a second, drifting copy
# of what the tags already say.
#
#   no-guess-dev   an untagged commit after v0.0.1 reads 0.0.1.post1.dev1
#                  rather than guessing the next release it might become.
#   no-local-version  drops the +g<sha> suffix, which is not a valid version
#                  for an index and makes tag-to-artifact comparison noisy.
[tool.hatch.version]
source = "vcs"
raw-options = { version_scheme = "no-guess-dev", local_scheme = "no-local-version" }
```

- [ ] **Step 2: Ship the policy module in the sdist**

In `[tool.hatch.build.targets.sdist]`'s `include` list, add `"tools/"` after `"tests/"`. The wheel deliberately does not get it: `tools/` is build tooling, and the wheel ships `spoonmap.py` alone.

- [ ] **Step 3: Verify the version actually resolves**

Run:
```bash
cd /tmp/spoonmap-auto-versioning && rm -rf dist && uv build 2>&1 | tail -3
```
Expected: two artifacts build. With no tags in the repo yet, the version reads `0.0.post1.devN` — that is correct for a zero baseline, not a bug. Confirm the tag path works too:

```bash
git tag v0.0.1-planverify && rm -rf dist && uv build 2>&1 | tail -2 && git tag -d v0.0.1-planverify && rm -rf dist
```
Expected: artifacts named `spoonmap-0.0.1...`. **Delete that scratch tag** — the command above does; confirm with `git tag` printing nothing.

- [ ] **Step 4: Stop the build job from mis-versioning silently**

In `.github/workflows/ci.yml`, the `build` job's checkout (~line 363) needs full history. Change it to:

```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          persist-credentials: false
          # hatch-vcs derives the version from git describe. Under the default
          # depth-1 clone this does not fail -- it silently produces a version
          # computed from no tag at all (0.0.post1.dev1 where the answer is
          # 0.0.1.post1.dev1), so every artifact this job inspects would carry
          # a version no release ever had.
          fetch-depth: 0
```

- [ ] **Step 5: Assert the built artifacts carry a real version**

Still in the `build` job, add a step after `Build sdist and wheel`:

```yaml
      - name: Assert artifacts carry a VCS-derived version
        run: |
          python3 - <<'PYEOF'
          import glob
          import os
          import sys

          # A depth-1 clone yields 0.0.post1.dev1 -- a version derived from no
          # tag. Once a tag exists, anything starting 0.0.post means the
          # checkout could not see it. This is the assertion that would have
          # caught a fetch-depth regression.
          names = [os.path.basename(p) for p in glob.glob('dist/*')]
          if not names:
              sys.exit('no artifacts were built')
          import subprocess
          tags = subprocess.run(
              ['git', 'tag'], capture_output=True, text=True, check=True
          ).stdout.split()
          if tags and any(n.startswith('spoonmap-0.0.post') for n in names):
              sys.exit(
                  'artifacts were versioned from no tag despite tags existing '
                  '(shallow checkout?): ' + ', '.join(names)
              )
          print('artifact versions: ' + ', '.join(names))
          PYEOF
```

- [ ] **Step 6: Run the suite and lint**

Run: `uv run pytest tests/ -q && uv run --frozen ruff check spoonmap.py tests/ tools/`
Expected: PASS, coverage still at or above 95%.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml .github/workflows/ci.yml
git commit -m "feat: derive the package version from git tags via hatch-vcs

Replaces the static version = \"0.1.0\", which had no relationship to
anything published and would drift the moment tags started being cut.

The build job's checkout gains fetch-depth: 0. A shallow clone does not
fail here -- verified -- it silently versions the artifacts from no tag at
all, which is why the job now asserts the version it produced."
```

---

### Task 3: The tagging workflows

> **Superseded in part, 2026-08-26.** The two `workflow_run`-triggered files
> below (`nightly-tag.yml`, `auto-tag.yml`) were built, then removed: zizmor —
> a required CI job — rates `workflow_run` an error-level dangerous trigger and
> exits 14, and this repo does not silence findings with ignore comments.
> Tagging is now a single `tag` job inside `.github/workflows/ci.yml`, gated on
> `needs: [test, test-legacy, lint, bandit, nse-root, workflow-lint, build]`
> and on `github.event_name == 'push'` for `main`/`nightly` only, with
> job-level `permissions: contents: write`. `release.yml` survives for
> hand-pushed tags but publishes via `gh release create` instead of a
> third-party action. The YAML below is kept as the record of what was tried
> and why it was rejected; see Tasks 6 and 7 for the current shape.

**Files:**
- Create: `.github/workflows/nightly-tag.yml`
- Create: `.github/workflows/auto-tag.yml`
- Create: `.github/workflows/release.yml`
- Modify: `.github/workflows/ci.yml` (push triggers, line 5-6)

**Interfaces:**
- Consumes: `python3 tools/next_version.py --channel {stable,nightly}` from Task 1 — prints a tag or prints nothing.
- Produces: tags `vX.Y.Z` on `main` and `vX.Y.ZrcN` on `nightly`, which Task 2's build reads.

**Two things that will silently do nothing if you get them wrong:**

1. `nightly-tag.yml` must exist on `main`. GitHub only dispatches `workflow_run` for workflows present on the *default* branch. A copy living only on `nightly` never fires. Since this branch merges to `nightly` and then down to `main`, that resolves itself — but do not "tidy" the file onto `nightly` only.
2. CI must actually run on `nightly`, or there is no successful CI run for `workflow_run` to key on. That is Step 1.

- [ ] **Step 1: Make CI run on the nightly branch**

In `.github/workflows/ci.yml`, change lines 5-6:

```yaml
  push:
    # `nightly` is here because nightly-tag.yml triggers on a completed CI run
    # for that branch. Without it, pushes to nightly run no CI at all and the
    # tagging workflow silently never fires.
    branches: [main, nightly]
```

- [ ] **Step 2: Create `.github/workflows/nightly-tag.yml`**

```yaml
name: Nightly Tag

# Tags `nightly` after CI passes, as a RELEASE CANDIDATE for whichever version
# the batch is heading toward: v0.0.1rc1, v0.0.1rc2, ... for a fix-only cycle,
# v0.1.0rc1 for one containing a feature. Merging down to main then promotes
# that same target to its final release.
#
# These are real PEP 440 pre-releases, so they order correctly at both ends:
#
#     0.0.0  <  0.0.1rc1  <  0.0.1rc2  <  0.0.1  <  0.1.0rc1  <  0.1.0
#
# Aiming one version forward is what makes that true. A candidate named for the
# *current* version would sort below the release it is heading for.
#
# The target can change mid-cycle: the first `feat` to land moves it from
# X.Y.(Z+1) to X.(Y+1).0 and candidate numbering restarts. That is intended --
# the number always names what the batch would ship as today.
#
# The policy lives in tools/next_version.py, shared with auto-tag.yml and
# unit-tested in tests/test_next_version.py. Nothing here parses or increments a
# version number. Do not add that here -- add to the module, where it is tested.
#
# No GitHub release is created; see the end of this file.
#
# This file MUST live on the default branch (main). GitHub only dispatches
# workflow_run for workflows present on the default branch, so a copy existing
# solely on `nightly` never fires.
on:
  workflow_run:
    workflows: ["CI"]
    types:
      - completed
    branches:
      - nightly

permissions:
  contents: write

# Two pushes landing back-to-back would otherwise both compute the same tag and
# the second push would fail. Serialize instead of cancelling so no push is
# skipped.
concurrency:
  group: nightly-tag
  cancel-in-progress: false

jobs:
  tag:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'push'
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          # workflow_run defaults to the tip of the default branch, which is not
          # the commit CI validated.
          ref: ${{ github.event.workflow_run.head_sha }}
          # The baseline is read from tags. Under a shallow clone the project
          # version reads as 0.0.0 and this would tag nonsense.
          fetch-depth: 0
          # Deliberate exception to this repo's persist-credentials: false
          # convention: this job pushes a tag and needs the token to do it.
          persist-credentials: true

      - name: Configure git identity
        run: |
          git config user.name 'github-actions[bot]'
          git config user.email '41898282+github-actions[bot]@users.noreply.github.com'

      - name: Compute nightly tag
        id: bump
        run: |
          set -euo pipefail
          # tools/next_version.py owns the decision; see the header. This step
          # deliberately contains no version logic of its own.
          new_tag=$(python3 tools/next_version.py --channel nightly)
          echo "Nightly tag: ${new_tag:-<nothing to tag>}"
          echo "new_tag=$new_tag" >> "$GITHUB_OUTPUT"

      - name: Create tag
        env:
          NEW_TAG: ${{ steps.bump.outputs.new_tag }}
        run: |
          set -euo pipefail
          # Empty means no commits since the last release: nothing to build a
          # candidate from. Not an error -- a workflow re-run lands here, and
          # `git tag ""` fails with a message about nothing in particular.
          if [ -z "$NEW_TAG" ]; then
            echo "No commits since the last release; nothing to tag"
            exit 0
          fi
          # Idempotent: a re-run of this workflow must not fail the job.
          if git rev-parse -q --verify "refs/tags/$NEW_TAG" >/dev/null; then
            echo "Tag $NEW_TAG already exists, nothing to push"
          else
            git tag "$NEW_TAG"
            git push origin "refs/tags/$NEW_TAG"
          fi

      # No GitHub release is created. These tags exist to make nightly builds
      # addressable and to give hatch-vcs a version; releases are cut on main by
      # auto-tag.yml.
```

- [ ] **Step 3: Create `.github/workflows/auto-tag.yml`**

```yaml
name: Auto Tag

# Cuts the stable release on main by promoting the candidate that `nightly` has
# been building: a fix-only cycle ends at X.Y.(Z+1), a cycle containing any
# feature ends at X.(Y+1).0.
#
# The bump is NOT forced per branch. main is not always X.Y.0. Deriving the bump
# from the batch is the point: forcing a minor on every merge takes a project
# two minor versions in an hour for two bugfixes.
#
# The policy lives in tools/next_version.py, shared with nightly-tag.yml and
# unit-tested in tests/test_next_version.py. Nothing here parses or increments a
# version number. Do not add that here -- add to the module, where it is tested.
#
# Runs only after CI finishes successfully on main, so a broken commit is never
# tagged or released.
on:
  workflow_run:
    workflows: ["CI"]
    types:
      - completed
    branches:
      - main

permissions:
  contents: write

# Two merges landing back-to-back would otherwise both compute the same new tag
# and the second push would fail. Serialize instead of cancelling so no merge is
# skipped.
concurrency:
  group: auto-tag
  cancel-in-progress: false

jobs:
  tag:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'push'
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          # workflow_run defaults to the tip of the default branch, which is not
          # necessarily the commit CI validated.
          ref: ${{ github.event.workflow_run.head_sha }}
          # The baseline is read from tags. Under a shallow clone the project
          # version reads as 0.0.0 and this would tag nonsense.
          fetch-depth: 0
          # Deliberate exception to this repo's persist-credentials: false
          # convention: this job pushes a tag and needs the token to do it.
          persist-credentials: true

      - name: Configure git identity
        run: |
          git config user.name 'github-actions[bot]'
          git config user.email '41898282+github-actions[bot]@users.noreply.github.com'

      - name: Compute release tag
        id: bump
        run: |
          set -euo pipefail
          # The whole decision -- which component moves, and to what -- is
          # tools/next_version.py's. Keeping it out of YAML is the point: this
          # step cannot be unit-tested and the policy can.
          new_tag=$(python3 tools/next_version.py --channel stable)
          echo "Release tag: ${new_tag:-<nothing to tag>}"
          echo "new_tag=$new_tag" >> "$GITHUB_OUTPUT"

      - name: Create tag
        env:
          NEW_TAG: ${{ steps.bump.outputs.new_tag }}
        run: |
          set -euo pipefail
          # Empty means no commits since the last release -- a re-run on an
          # already-released commit. Nothing to do, and not an error.
          #
          # This is not a "no feat/fix commits, skip" early exit: a docs- or
          # chore-only merge is still a release, it just cuts a patch rather
          # than a minor. Only a genuinely empty batch is skipped.
          if [ -z "$NEW_TAG" ]; then
            echo "No commits since the last release; nothing to tag"
            exit 0
          fi
          # Idempotent: a re-run of this workflow must not fail the job.
          if git rev-parse -q --verify "refs/tags/$NEW_TAG" >/dev/null; then
            echo "Tag $NEW_TAG already exists, nothing to push"
          else
            git tag "$NEW_TAG"
            git push origin "refs/tags/$NEW_TAG"
          fi

      # GitHub never dispatches workflow events for refs pushed with
      # GITHUB_TOKEN, so release.yml will not fire for the tag above. Create the
      # release here instead. release.yml remains the path for tags pushed
      # manually by a human.
      - name: Create GitHub release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NEW_TAG: ${{ steps.bump.outputs.new_tag }}
        run: |
          set -euo pipefail
          if [ -z "$NEW_TAG" ]; then
            echo "No tag was created; no release to publish"
            exit 0
          fi
          if gh release view "$NEW_TAG" >/dev/null 2>&1; then
            echo "Release $NEW_TAG already exists, nothing to do"
            exit 0
          fi
          gh release create "$NEW_TAG" --generate-notes
```

- [ ] **Step 4: Create `.github/workflows/release.yml`**

```yaml
name: Release

# The path for tags a human pushes by hand. The automatic policy never bumps the
# major component -- a breaking marker counts as a feature, because an automatic
# major is an irreversible published mistake waiting for one mistyped subject
# line -- so a major release is `git tag v1.0.0 && git push`, and this is what
# turns that into a release.
#
# Tags pushed by auto-tag.yml do NOT reach here: GitHub does not dispatch
# workflow events for refs pushed with GITHUB_TOKEN. That job creates its own
# release.
on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          # Read-only: this job creates a release from a tag that already
          # exists, so unlike the two tagging workflows it needs no credentials.
          persist-credentials: false

      - uses: softprops/action-gh-release@3d0d9888cb7fd7b750713d6e236d1fcb99157228  # v3.0.2
        with:
          generate_release_notes: true
```

- [ ] **Step 5: Lint the workflows the way CI will**

Run:
```bash
cd /tmp/spoonmap-auto-versioning
uvx actionlint .github/workflows/*.yml
uvx zizmor .github/workflows/
```
Expected: no errors. zizmor will likely flag `persist-credentials: true` on the two tagging jobs. If it fails the run rather than merely noting it, do **not** silence it with an inline ignore — check how the existing `workflow-lint` job invokes zizmor (`.github/workflows/ci.yml`, job `workflow-lint`) and match whatever severity threshold it already uses. Report the finding in your summary either way.

- [ ] **Step 6: Prove the computed tag is what gets pushed, locally**

Before trusting any of this in CI, run the policy against this very repository:

```bash
cd /tmp/spoonmap-auto-versioning
python3 tools/next_version.py --channel nightly
python3 tools/next_version.py --channel stable
```
Expected: with no tags and this branch's history, both print something. Record both values in your task summary — if `--channel nightly` prints `v0.1.0rc1` rather than `v0.0.1rc1`, some commit in the repo's history says `feat:`, which is the first-batch consequence the spec calls out.

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/
git commit -m "feat: tag releases automatically from CI on main and nightly

nightly cuts vX.Y.ZrcN candidates, main promotes the same target to its
final release and publishes it. Both call tools/next_version.py; neither
does version arithmetic in YAML.

ci.yml now runs on pushes to nightly. It did not before, so there would
have been no successful CI run for nightly-tag.yml's workflow_run trigger
to key on and it would have silently never fired."
```

---

### Task 4: `--version`

**Files:**
- Modify: `spoonmap.py` (new `_tool_version()` near `_operator_dir()`; dispatch in `main()` around line 5855)
- Test: `tests/test_spoonmap.py`

**Interfaces:**
- Consumes: distribution metadata produced by Task 2.
- Produces: `_tool_version() -> str` and `_UNKNOWN_VERSION` — Task 5's update check calls both.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_spoonmap.py` (put the class next to the other small-helper test classes):

Note the existing conventions in that file: it imports `from unittest.mock import MagicMock, patch`, so use bare `patch` / `MagicMock`, not `mock.patch`.

```python
class TestToolVersion:
    """_tool_version() reports the installed version, or says it cannot."""

    def test_reports_the_installed_distribution_version(self):
        with patch('spoonmap.metadata.version', return_value='1.2.3'):
            assert spoonmap._tool_version() == '1.2.3'

    def test_running_from_a_checkout_is_not_a_version(self):
        """No distribution metadata exists when spoonmap.py is run as a plain
        script from a clone, which is the documented invocation. That must read
        as 'unknown', never as a version number that could be compared."""
        with patch('spoonmap.metadata.version',
                   side_effect=spoonmap.metadata.PackageNotFoundError):
            assert spoonmap._tool_version() == spoonmap._UNKNOWN_VERSION

    def test_the_unknown_sentinel_is_not_mistakable_for_a_version(self):
        assert not spoonmap._UNKNOWN_VERSION[0].isdigit()
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestToolVersion -v`
Expected: FAIL — `AttributeError: module 'spoonmap' has no attribute '_tool_version'`.

- [ ] **Step 3: Implement**

In `spoonmap.py`, add to the imports at the top:

```python
from importlib import metadata
```

Then add, immediately after `_operator_dir()` (near line 2459, beside `_DIR`/`_NSE_DIR`):

```python
# What _tool_version() reports when there is no distribution metadata to read.
# Deliberately not a number: it flows into the update check, where anything
# parseable as a version would be compared against the latest release and
# produce a confident wrong answer.
_UNKNOWN_VERSION = 'unknown (running from source)'


def _tool_version():
    """The installed SpooNMAP version, or _UNKNOWN_VERSION.

    Read from distribution metadata rather than a string in this file, because
    the version is derived from git tags at build time (see pyproject.toml's
    [tool.hatch.version]) and a literal here would be a second, drifting copy.

    The documented invocation `./spoonmap.py` from a clone installs nothing, so
    PackageNotFoundError is the *normal* case for a developer or an operator
    running from a checkout -- not an error worth a warning.
    """
    try:
        return metadata.version('spoonmap')
    except metadata.PackageNotFoundError:
        return _UNKNOWN_VERSION
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_spoonmap.py::TestToolVersion -v`
Expected: PASS.

- [ ] **Step 5: Wire up the flag**

In `main()`, the `--cleanup` dispatch currently reads:

```python
        if '--cleanup' in sys.argv:
            _cleanup_cmd(dir_path)  # prints result and exits
```

`--version` must print a clean, scriptable line with no banner above it, so handle it *before* `ascii_art()`. At the very top of `main()`, immediately after `global output_path` and before `initial_term_state = save_terminal_state()`, insert:

```python
    # Handled before the banner and before any terminal state is touched:
    # `spoonmap --version` should emit one parseable line and nothing else.
    if '--version' in sys.argv:
        print(_tool_version())
        sys.exit(0)
```

- [ ] **Step 6: Verify by hand**

Run: `cd /tmp/spoonmap-auto-versioning && python3 spoonmap.py --version`
Expected: prints exactly `unknown (running from source)` and exits 0, with no ASCII banner. (`unknown` is correct here — this is a checkout, not an install.)

- [ ] **Step 7: Full suite, lint, commit**

```bash
uv run pytest tests/ -q
uv run --frozen ruff check spoonmap.py tests/ tools/
uv run --frozen bandit -r spoonmap.py -c pyproject.toml -b .bandit-baseline.json
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: add --version

Reads the version from distribution metadata rather than a literal in
spoonmap.py, since the version is derived from git tags at build time and a
literal would be a second copy that drifts.

Running from a checkout has no metadata to read, which is the documented
invocation, so that reports a non-numeric 'unknown' sentinel rather than a
number the update check could compare against."
```

---

### Task 5: Opt-in update checking

**Files:**
- Modify: `spoonmap.py` (three new functions; `_load_config()` at line 5708; `main()` dispatch)
- Modify: `config.json.sample`
- Test: `tests/test_spoonmap.py`

**Interfaces:**
- Consumes: `_tool_version()`, `_UNKNOWN_VERSION` (Task 4); the existing `_config_bool(key, value, default)` (line 5621) and `_COLOR_ERROR` / `_COLOR_RESET`.
- Produces: `_parse_release_tag(tag) -> Optional[tuple]`, `_check_for_updates(timeout=...) -> None`, `_maybe_check_for_updates(enabled) -> None`, and a `'check_for_updates'` key in `_load_config()`'s returned dict.

**Correction to the spec:** the spec says to add a `_config_bool()` helper. It already exists at `spoonmap.py:5621` and already accepts both JSON booleans and the legacy quoted spellings. Use it; do not add a second one.

**The rule this task exists to enforce:** SpooNMAP runs from jumpboxes inside client networks. Nothing here may touch the network at launch unless the operator explicitly set `check_for_updates` to true. Absent key means off. Step 1's first test is the one that holds that line.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_spoonmap.py`:

```python
class TestUpdateCheckIsOptIn:
    """The launch-time update check is off unless explicitly enabled.

    SpooNMAP runs from jumpboxes inside client networks, where an unprompted
    call to api.github.com is an outbound beacon from an engagement host that
    nobody authorised. hate_crack defaults this to True; SpooNMAP inverts it,
    and these tests are what keep it inverted.
    """

    def test_a_config_that_never_mentions_the_key_makes_no_network_call(self):
        def explode(*args, **kwargs):
            raise AssertionError(
                'a default config performed a network call at launch'
            )

        with patch('spoonmap.urllib.request.urlopen', side_effect=explode):
            spoonmap._maybe_check_for_updates(False)

    def test_enabling_it_performs_the_check(self):
        with patch('spoonmap._check_for_updates') as checked:
            spoonmap._maybe_check_for_updates(True)
        checked.assert_called_once()

    def test_load_config_defaults_the_key_to_false(self):
        cfg = _config_dict()
        assert 'check_for_updates' not in cfg
        assert _load_config(cfg, '/t')['check_for_updates'] is False

    def test_load_config_honours_an_explicit_true(self):
        cfg = _config_dict(check_for_updates=True)
        assert _load_config(cfg, '/t')['check_for_updates'] is True

    def test_load_config_accepts_the_legacy_quoted_spelling(self):
        """_config_bool() accepts "True"/"False" indefinitely for hand-edited
        configs; this key is no exception."""
        cfg = _config_dict(check_for_updates='True')
        assert _load_config(cfg, '/t')['check_for_updates'] is True


class TestCheckForUpdates:
    """The check itself: comparison, output, and total failure tolerance."""

    def _response(self, tag):
        body = json.dumps({'tag_name': tag}).encode()
        resp = MagicMock()
        resp.read.return_value = body
        resp.__enter__.return_value = resp
        return resp

    def test_a_newer_release_is_reported(self, capsys):
        with patch('spoonmap._tool_version', return_value='0.0.1'), \
             patch('spoonmap.urllib.request.urlopen',
                        return_value=self._response('v0.1.0')):
            spoonmap._check_for_updates()
        out = capsys.readouterr().out
        assert '0.1.0' in out

    def test_being_up_to_date_says_so_without_claiming_an_update(self, capsys):
        with patch('spoonmap._tool_version', return_value='0.1.0'), \
             patch('spoonmap.urllib.request.urlopen',
                        return_value=self._response('v0.1.0')):
            spoonmap._check_for_updates()
        assert 'Update available' not in capsys.readouterr().out

    def test_an_older_release_is_not_an_update(self, capsys):
        with patch('spoonmap._tool_version', return_value='0.2.0'), \
             patch('spoonmap.urllib.request.urlopen',
                        return_value=self._response('v0.1.0')):
            spoonmap._check_for_updates()
        assert 'Update available' not in capsys.readouterr().out

    def test_an_unknown_local_version_never_claims_an_update(self, capsys):
        """Running from a checkout has no version to compare. Reporting the
        latest release is fine; asserting the operator is behind is not --
        it would nag everyone running from a clone, which is most of them."""
        with patch('spoonmap._tool_version',
                        return_value=spoonmap._UNKNOWN_VERSION), \
             patch('spoonmap.urllib.request.urlopen',
                        return_value=self._response('v0.1.0')):
            spoonmap._check_for_updates()
        out = capsys.readouterr().out
        assert 'Update available' not in out
        assert '0.1.0' in out

    def test_a_network_failure_is_swallowed(self, capsys):
        """A failed update check must never delay, prompt, or abort a scan."""
        with patch('spoonmap._tool_version', return_value='0.0.1'), \
             patch('spoonmap.urllib.request.urlopen',
                        side_effect=OSError('no route to host')):
            spoonmap._check_for_updates()  # must not raise
        assert 'Update available' not in capsys.readouterr().out

    def test_unparseable_json_is_swallowed(self, capsys):
        resp = MagicMock()
        resp.read.return_value = b'<html>404</html>'
        resp.__enter__.return_value = resp
        with patch('spoonmap._tool_version', return_value='0.0.1'), \
             patch('spoonmap.urllib.request.urlopen', return_value=resp):
            spoonmap._check_for_updates()  # must not raise

    def test_a_release_with_no_tag_name_is_swallowed(self, capsys):
        resp = MagicMock()
        resp.read.return_value = b'{}'
        resp.__enter__.return_value = resp
        with patch('spoonmap._tool_version', return_value='0.0.1'), \
             patch('spoonmap.urllib.request.urlopen', return_value=resp):
            spoonmap._check_for_updates()  # must not raise


class TestParseReleaseTag:
    """Version comparison, without a packaging dependency."""

    @pytest.mark.parametrize('text,expected', [
        ('v0.1.0', (0, 1, 0)),
        ('0.1.0', (0, 1, 0)),
        ('v10.4.7', (10, 4, 7)),
        # Not a comparable release: a candidate, a dev build, junk, and the
        # running-from-source sentinel.
        ('v0.1.0rc1', None),
        ('0.0.1.post1.dev1', None),
        ('nightly', None),
        ('', None),
    ])
    def test_only_plain_releases_compare(self, text, expected):
        assert spoonmap._parse_release_tag(text) == expected

    def test_comparison_is_numeric_not_lexical(self):
        assert (spoonmap._parse_release_tag('v0.10.0')
                > spoonmap._parse_release_tag('v0.9.0'))
```

`_config_dict(**overrides)` and `_load_config` are already defined in `tests/test_spoonmap.py` (line 2375 and the module's import block respectively) — use them as-is, do not add a second helper. `json`, `pytest`, `patch` and `MagicMock` are already imported there too.

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py -k "UpdateCheck or CheckForUpdates or ParseReleaseTag" -v`
Expected: FAIL — the three functions do not exist.

- [ ] **Step 3: Implement**

Add to `spoonmap.py`'s imports: `import urllib.error` and `import urllib.request` (`json` and `re` are already imported; confirm).

Add these functions immediately after `_tool_version()` from Task 4:

```python
# Latest *release* specifically: GitHub's /releases/latest excludes
# pre-releases, so the vX.Y.ZrcN candidates cut on `nightly` are never
# advertised to an operator as an available update.
_RELEASE_API_URL = (
    'https://api.github.com/repos/trustedsec/spoonmap/releases/latest'
)
_RELEASES_URL = 'https://github.com/trustedsec/spoonmap/releases'
# Short: this runs before a scan, and a hung TCP connection to a network the
# jumpbox cannot reach must not become a stalled engagement.
_UPDATE_CHECK_TIMEOUT = 5

_RELEASE_TAG_RE = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)$')


def _parse_release_tag(text):
    """(major, minor, patch) for a plain release, else None.

    Deliberately strict. A candidate (0.1.0rc1) or a dev build
    (0.0.1.post1.dev1) is not comparable against a release without PEP 440
    semantics, and spoonmap.py is stdlib-only by design -- there is no
    `packaging` here to do it properly, so anything that is not an unambiguous
    X.Y.Z is declined rather than guessed at.
    """
    match = _RELEASE_TAG_RE.match((text or '').strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _check_for_updates(timeout=_UPDATE_CHECK_TIMEOUT):
    """Report whether a newer release exists. Never raises, never blocks long.

    Every failure mode -- no route, DNS, TLS, rate limiting, an HTML error page
    where JSON was expected, a release with no tag_name -- is swallowed. An
    update check is a courtesy; a scan must never fail or stall because one did.
    """
    try:
        with urllib.request.urlopen(_RELEASE_API_URL, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode('utf-8', 'replace'))
        latest_text = payload.get('tag_name', '')
    except Exception:
        # Intentionally broad: see the docstring. There is no failure here
        # worth interrupting an operator for, and the set of exceptions urllib
        # and json can raise between them is not worth enumerating wrongly.
        return

    latest = _parse_release_tag(latest_text)
    if latest is None:
        return

    current_text = _tool_version()
    current = _parse_release_tag(current_text)
    if current is None:
        # Running from a checkout, or on a dev build. There is nothing to
        # compare, so report the fact and make no claim about it -- telling
        # every operator running from a clone that they are out of date would
        # be wrong far more often than right.
        print(f'Latest release: {latest_text} (local version unknown). '
              f'See {_RELEASES_URL}')
        return

    if latest > current:
        print(_COLOR_ERROR
              + f'Update available: {latest_text} (current: {current_text}). '
                f'See {_RELEASES_URL}'
              + _COLOR_RESET)
    else:
        print(f'SpooNMAP {current_text} is up to date.')


def _maybe_check_for_updates(enabled):
    """Run the update check only if the operator turned it on.

    Separate from _check_for_updates() so the gate itself is testable: main()
    is under `pragma: no cover`, and "does a default config reach the network"
    is exactly the question that must not go untested.
    """
    if enabled:
        _check_for_updates()
```

- [ ] **Step 4: Add the config key**

In `_load_config()`, beside the other `_config_bool` calls (near `banner_scan`, line ~5752), add:

```python
    # Absent means off, and absent is the normal case. This is the only way to
    # enable a launch-time network call; see _check_for_updates().
    check_for_updates = _config_bool(
        'check_for_updates', config_parser.get('check_for_updates', False), False)
```

and add `'check_for_updates': check_for_updates,` to the dict `_load_config()` returns. Do **not** add it to `_CONFIG_REQUIRED_KEYS` — a config that never mentions it must stay valid.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/test_spoonmap.py -k "UpdateCheck or CheckForUpdates or ParseReleaseTag" -v`
Expected: PASS.

- [ ] **Step 6: Wire up `--check-update` and the config-gated call**

In `main()`, extend the block added in Task 4 Step 5 so it reads:

```python
    # Handled before the banner and before any terminal state is touched:
    # `spoonmap --version` should emit one parseable line and nothing else.
    if '--version' in sys.argv:
        print(_tool_version())
        sys.exit(0)
    # On-demand, regardless of config: asking whether an update exists should
    # not require leaving the launch-time check switched on.
    if '--check-update' in sys.argv:
        _check_for_updates()
        sys.exit(0)
```

Then, at the point where the loaded config's values are unpacked (after `cfg = _load_config(config_parser, dir_path, resume)`), add:

```python
            _maybe_check_for_updates(cfg['check_for_updates'])
```

There is no equivalent call on the interactive path: a config that does not exist cannot have opted in.

- [ ] **Step 7: Document the key in `config.json.sample`**

Add these two lines before `"target_file"`, matching the file's existing `__note__` convention:

```json
    "__check_for_updates_note__": "Optional. When true, SpooNMAP contacts api.github.com at startup to see whether a newer release exists. Default false, and absent means false: the tool makes no network connection other than the scan itself unless you turn this on. Use --check-update for a one-off check without enabling it here.",
    "check_for_updates": false,
```

- [ ] **Step 8: Verify by hand, including the flag**

```bash
cd /tmp/spoonmap-auto-versioning
python3 spoonmap.py --check-update
python3 -c "import json; json.load(open('config.json.sample')); print('sample is valid JSON')"
```
Expected: the first prints either a latest-release line or nothing at all (if the network is unavailable — that is the swallowed path working, not a failure); the second confirms the sample still parses.

- [ ] **Step 9: Full suite, lint, SAST**

```bash
uv run pytest tests/ -q
uv run --frozen ruff check spoonmap.py tests/ tools/
uv run --frozen bandit -r spoonmap.py -c pyproject.toml -b .bandit-baseline.json
```

Bandit will likely raise **B310 (`urllib.request.urlopen` with an unverified scheme)** — it is scheme-blind even for a hardcoded `https://` literal. Per this repo's rules, do **not** add `# nosec`. Regenerate the baseline instead and justify it:

```bash
uv run --frozen bandit -r spoonmap.py -c pyproject.toml -f json -o .bandit-baseline.json
git diff --stat .bandit-baseline.json
```

Read the diff before staging it. Exactly one new finding should appear, for the `urlopen` call. If more appeared, stop and report — something else changed.

- [ ] **Step 10: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py config.json.sample .bandit-baseline.json
git commit -m "feat: add opt-in update checking, off by default

hate_crack's equivalent defaults check_for_updates to True and calls out to
api.github.com on every launch. SpooNMAP runs from jumpboxes inside client
networks, where that is an unauthorised outbound beacon from an engagement
host, so the key defaults to false and absent means false.

The gate lives in _maybe_check_for_updates() rather than inline in main(),
which is under pragma: no cover -- 'does a default config reach the
network' is the one question here that must not go untested, and its test
patches urlopen to raise if it is called at all.

Baseline regenerated for one new bandit B310 on the urlopen call. The URL
is a hardcoded https literal; B310 is scheme-blind and cannot see that."
```

---

### Task 6: Guard the wiring that breaks silently

> **Design change, 2026-08-26 (supersedes this task's original form).** Tagging
> no longer lives in separate `workflow_run`-triggered workflows. zizmor — a
> required CI job — rejects `workflow_run` at error level as a
> privilege-escalation vector and exits 14, and this repo does not silence
> findings with ignore comments. Tagging is now a single `tag` job inside
> `.github/workflows/ci.yml`, gated on `needs: [test, test-legacy, lint,
> bandit, nse-root, workflow-lint, build]` and `if: github.event_name ==
> 'push'` restricted to `main`/`nightly`, with job-level `permissions: contents:
> write`. `auto-tag.yml` and `nightly-tag.yml` no longer exist. `release.yml`
> remains, for hand-pushed tags, and publishes via `gh release create` rather
> than a third-party action.

**Files:**
- Create: `tests/test_release_versioning.py`
- Modify: `pyproject.toml` (dev group gains `pyyaml`)
- Modify: `.github/workflows/ci.yml` (`test-legacy` job's `uv run` line, ~line 118; `lint` job's ruff line, ~line 151)

**Interfaces:**
- Consumes: the `tag` job in `ci.yml` and `release.yml` from Task 3, `tools/next_version.py` from Task 1.
- Produces: nothing other tasks consume.

The policy is already tested. What is untested is everything around it: a tag
job that stops depending on a test job, a step that stops using the policy
module, a tag pushed without being the one that was computed, a `fetch-depth`
quietly reverted. Those fail *silently* — no tag simply appears, or a wrong one
does, and nobody notices for weeks.

Assert behaviour by running the extracted step scripts, not by
substring-matching YAML. hate_crack learned this the hard way: its substring
assertions were defeated by replacing an entire `if`/`else` with an
unconditional `git tag && git push`, and every test still passed because the
substring lived elsewhere in the file.

- [ ] **Step 1: Make the test dependencies available on every job**

In `pyproject.toml`'s `[dependency-groups].dev`, add:

```toml
    # Test-only. tests/test_release_versioning.py parses the workflow YAML to
    # assert the CI triggers and tagging steps still wire together.
    "pyyaml>=6.0",
```

Then in `.github/workflows/ci.yml`, the `test-legacy` job resolves its own
dependencies outside the project (`uv run --isolated --no-project ... --with
pytest --with pytest-cov`), so it would hit an ImportError collecting the new
modules. Extend that line:

```yaml
      - name: Run tests
        run: >
          uv run --isolated --no-project --python ${{ matrix.python-version }}
          --with pytest --with pytest-cov --with pyyaml --with packaging
          pytest tests/ -v -rs
```

`packaging` is for `tests/test_next_version.py`. It currently resolves only
because pytest happens to depend on it transitively — one pytest release away
from breaking. Do not solve any of this with `pytest.importorskip`: a skipped
guard is a guard that silently is not running, which is the exact failure this
whole file exists to prevent.

Also extend the `lint` job's ruff invocation (~line 151) to cover the new
directory, which is currently never linted in CI:

```yaml
      - name: Ruff
        run: uv run --frozen ruff check spoonmap.py tests/ tools/
```

Run `uv lock` after editing the dev group.

- [ ] **Step 2: Write the tests**

Create `tests/test_release_versioning.py`:

```python
"""Guards on the release-versioning wiring.

The policy itself -- which component moves, and to what -- lives in
tools/next_version.py and is tested in tests/test_next_version.py. Nothing here
re-implements it.

What this file guards is everything around the policy, all of which fails
*silently*:

* The tag job ceasing to depend on the jobs that validate the commit, which
  would let a tag land on a commit that failed its tests.
* The policy module ceasing to be the only thing that produces a version,
  asserted as a positive invariant (exactly one next_version.py call, and the
  pushed tag read back from its output) with a denylist of shell version
  arithmetic as a second line of defence.
* A `fetch-depth` reverted to the default, which does not fail anything -- it
  silently computes versions from a baseline of no tags at all.
* The behaviour of the shell that remains -- tag idempotency and the
  empty-batch path -- asserted by extracting the step script from the YAML and
  running it against a real git repository and a real bare remote.

Substring assertions on YAML are sensitive to formatting and blind to
behaviour, which is backwards. Do not convert these back into them.
"""

import os
import re
import subprocess

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(REPO_ROOT, '.github', 'workflows')


def _load(name):
    with open(os.path.join(WORKFLOWS, name)) as handle:
        return yaml.safe_load(handle)


# `on` is the YAML 1.1 boolean True, so a parsed workflow keys the trigger
# block under True rather than 'on'. This bites everyone once.
def _triggers(workflow):
    return workflow.get('on', workflow.get(True))


def _job(name, job_id):
    return _load(name)['jobs'][job_id]


def _step_script(job, step_name):
    for step in job['steps']:
        if step.get('name') == step_name:
            return step['run']
    raise AssertionError(f'no step named {step_name!r}')


def _checkout(job):
    for step in job['steps']:
        if 'actions/checkout' in str(step.get('uses', '')):
            return step
    raise AssertionError('no checkout step')


# --- triggers and gating -----------------------------------------------------


def test_ci_runs_on_pushes_to_both_release_branches():
    """A push to `nightly` that runs no CI would never reach the tag job, and
    no candidate would ever be cut. Nothing errors; tags just stop appearing."""
    branches = _triggers(_load('ci.yml'))['push']['branches']
    assert 'nightly' in branches
    assert 'main' in branches


def test_the_tag_job_waits_for_every_validating_job():
    """A tag must never appear on a commit that failed anything. `needs` treats
    a failed or skipped dependency as not-success, so the job simply does not
    run -- but only for jobs actually listed here."""
    ci = _load('ci.yml')
    needs = set(ci['jobs']['tag']['needs'])
    validating = {j for j in ci['jobs'] if j != 'tag'}
    missing = validating - needs
    assert not missing, f'tag job does not depend on: {sorted(missing)}'


def test_the_tag_job_never_runs_on_pull_requests():
    """ci.yml also runs on pull_request, where tagging would be actively
    wrong."""
    condition = _job('ci.yml', 'tag')['if']
    assert "github.event_name == 'push'" in condition
    assert "refs/heads/main" in condition
    assert "refs/heads/nightly" in condition


def test_only_the_tag_job_can_write():
    """The workflow is read-only; exactly one job escalates, and only to what
    pushing a tag and cutting a release requires."""
    ci = _load('ci.yml')
    assert ci['permissions'] == {'contents': 'read'}
    assert ci['jobs']['tag']['permissions'] == {'contents': 'write'}
    for job_id, job in ci['jobs'].items():
        if job_id != 'tag':
            assert 'permissions' not in job, job_id


def test_the_tag_job_does_not_cancel_itself():
    """Two pushes landing together would compute the same tag; the second push
    would fail. Serialize per branch rather than cancel, so none is skipped."""
    concurrency = _job('ci.yml', 'tag')['concurrency']
    assert concurrency['cancel-in-progress'] is False


# --- checkout depth ----------------------------------------------------------


@pytest.mark.parametrize('job_id', ['tag', 'build'])
def test_version_deriving_jobs_fetch_all_history(job_id):
    """Both jobs derive a version from git describe. A shallow clone does not
    fail either of them -- it silently computes from a baseline of no tags,
    which is how a wrong version ships without anything going red."""
    assert _checkout(_job('ci.yml', job_id))['with']['fetch-depth'] == 0


def test_the_tag_job_keeps_its_credentials():
    """Deliberate exception to this repo's persist-credentials: false rule:
    this job pushes a tag and needs the token. Pinned so a well-meaning
    convention sweep cannot silently break tagging."""
    assert _checkout(_job('ci.yml', 'tag'))['with']['persist-credentials'] is True


def test_every_other_checkout_drops_its_credentials():
    ci = _load('ci.yml')
    for job_id, job in ci['jobs'].items():
        if job_id == 'tag':
            continue
        assert _checkout(job)['with']['persist-credentials'] is False, job_id


# --- the policy module is the only thing that produces a version -------------


def test_exactly_one_call_to_the_policy_module():
    with open(os.path.join(WORKFLOWS, 'ci.yml')) as handle:
        body = handle.read()
    calls = re.findall(r'tools/next_version\.py --channel', body)
    assert len(calls) == 1, 'the tag must come from exactly one call'


def test_both_channels_are_reachable():
    """main cuts the final release, nightly cuts a candidate for the same
    target. A job that only ever computed one channel would silently tag
    nightly builds as releases, or never cut a release at all."""
    script = _step_script(_job('ci.yml', 'tag'), 'Compute tag')
    assert 'channel=stable' in script
    assert 'channel=nightly' in script


def test_the_pushed_tag_is_the_one_the_policy_computed():
    job = _job('ci.yml', 'tag')
    compute = [s for s in job['steps'] if 'next_version.py' in s.get('run', '')]
    assert len(compute) == 1
    step_id = compute[0]['id']
    create = [s for s in job['steps'] if s.get('name') == 'Create tag'][0]
    assert create['env']['NEW_TAG'] == '${{ steps.%s.outputs.new_tag }}' % step_id


def test_no_shell_version_arithmetic():
    """Second line of defence. Version math in YAML cannot be unit-tested,
    which is the entire reason tools/next_version.py exists."""
    with open(os.path.join(WORKFLOWS, 'ci.yml')) as handle:
        body = handle.read()
    for banned in ('cut -d.', '$((', 'awk -F.'):
        assert banned not in body, f'version arithmetic in YAML: {banned}'


def test_only_stable_publishes_a_release():
    """Nightly candidates exist to make builds addressable, not to be releases.
    Publishing them would make anything ranking releases see a candidate as
    latest."""
    release_step = [
        s for s in _job('ci.yml', 'tag')['steps']
        if s.get('name') == 'Create GitHub release'
    ][0]
    assert "== 'stable'" in release_step['if']


# --- the behaviour of the shell that remains ---------------------------------


def _git(repo, *args):
    return subprocess.run(
        ['git', *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture
def repo_with_remote(tmp_path):
    """A real repository with a real bare origin, so `git push` is exercised."""
    remote = tmp_path / 'remote.git'
    subprocess.run(['git', 'init', '-q', '--bare', str(remote)], check=True)
    repo = tmp_path / 'repo'
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    _git(repo, 'config', 'user.email', 'test@example.com')
    _git(repo, 'config', 'user.name', 'test')
    (repo / 'f.txt').write_text('x')
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-qm', 'fix: initial')
    _git(repo, 'remote', 'add', 'origin', str(remote))
    return repo, remote


def _run_create_tag(repo, script, new_tag):
    env = dict(os.environ, NEW_TAG=new_tag)
    return subprocess.run(
        ['bash', '-c', script], cwd=repo, env=env,
        capture_output=True, text=True,
    )


def test_create_tag_pushes_the_tag(repo_with_remote):
    repo, remote = repo_with_remote
    script = _step_script(_job('ci.yml', 'tag'), 'Create tag')
    result = _run_create_tag(repo, script, 'v0.1.0')
    assert result.returncode == 0, result.stderr
    assert 'v0.1.0' in _git(remote, 'tag')


def test_create_tag_is_idempotent(repo_with_remote):
    """A re-run of the workflow must not fail the job."""
    repo, _ = repo_with_remote
    script = _step_script(_job('ci.yml', 'tag'), 'Create tag')
    assert _run_create_tag(repo, script, 'v0.1.0').returncode == 0
    second = _run_create_tag(repo, script, 'v0.1.0')
    assert second.returncode == 0, second.stderr


def test_an_empty_batch_tags_nothing_and_is_not_an_error(repo_with_remote):
    """No commits since the last release is a re-run, not a failure. Tagging
    "" would fail with a message about nothing in particular."""
    repo, remote = repo_with_remote
    script = _step_script(_job('ci.yml', 'tag'), 'Create tag')
    result = _run_create_tag(repo, script, '')
    assert result.returncode == 0, result.stderr
    assert _git(remote, 'tag').strip() == ''


def test_the_policy_module_agrees_with_this_repository():
    """End to end against the real repo: the CLI runs and prints a usable tag
    or nothing at all. Catches an import error or a bad shebang that no unit
    test would see."""
    result = subprocess.run(
        ['python3', os.path.join(REPO_ROOT, 'tools', 'next_version.py'),
         '--channel', 'nightly', '--repo-dir', REPO_ROOT],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    output = result.stdout.strip()
    assert output == '' or re.match(r'^v\d+\.\d+\.\d+rc\d+$', output), output


# --- the hand-pushed release path -------------------------------------------


def test_release_workflow_still_exists_for_hand_pushed_tags():
    """The policy never bumps a major automatically, so a major release is
    `git tag v1.0.0 && git push`. This is what turns that into a release."""
    assert _triggers(_load('release.yml'))['push']['tags'] == ['v*']


def test_the_release_workflow_uses_no_third_party_action():
    """The runner already ships gh, and the tag job publishes the same way.
    zizmor flags the third-party action as superfluous, and two release paths
    doing the same thing differently is one too many."""
    (job,) = _load('release.yml')['jobs'].values()
    for step in job['steps']:
        uses = str(step.get('uses', ''))
        assert 'action-gh-release' not in uses
```

- [ ] **Step 3: Run them**

Run: `uv run pytest tests/test_release_versioning.py -v`
Expected: PASS. If `_triggers()` returns `None`, the workflow parsed `on` as the
boolean `True` — that is what the helper handles; check you copied it intact.

- [ ] **Step 4: Prove the guards actually guard**

A test that cannot fail is not a guard. Mutate and confirm each bites, on a
scratch copy so the real file is never left broken:

```bash
cd /tmp/spoonmap-auto-versioning
cp .github/workflows/ci.yml /tmp/ci.yml.good
python3 - <<'EOF'
p = '.github/workflows/ci.yml'
s = open(p).read().replace('branches: [main, nightly]', 'branches: [main]')
open(p, 'w').write(s)
EOF
uv run pytest tests/test_release_versioning.py::test_ci_runs_on_pushes_to_both_release_branches -q
# Expected: FAIL
cp /tmp/ci.yml.good .github/workflows/ci.yml
```

Repeat, restoring from `/tmp/ci.yml.good` each time, for three more:

- Remove `fetch-depth: 0` from the `build` job's checkout → `test_version_deriving_jobs_fetch_all_history[build]` must FAIL. (This is the guard that replaces the dormant artifact-version assertion, which cannot fire while the repo has no tags.)
- Drop one job from the `tag` job's `needs` list → `test_the_tag_job_waits_for_every_validating_job` must FAIL.
- Replace the `Create tag` step's `if`/`else` with an unconditional `git tag "$NEW_TAG" && git push origin "refs/tags/$NEW_TAG"` → both `test_create_tag_is_idempotent` and `test_an_empty_batch_tags_nothing_and_is_not_an_error` must FAIL.

Report all four mutation results with real output. "The tests pass" is not evidence here.

- [ ] **Step 5: Confirm nothing is left mutated**

Run: `git diff --stat && uv run pytest tests/ -q`
Expected: the only diffs are the intended new/modified files, and the full suite
passes at or above 95% coverage.

- [ ] **Step 6: Commit**

```bash
git add tests/test_release_versioning.py pyproject.toml uv.lock .github/workflows/ci.yml
git commit -m "test: guard the release-versioning wiring

The policy is unit-tested; the wiring around it is what fails silently. A
tag job that stops depending on a test job, a step that stops calling
next_version.py, a reverted fetch-depth, or a tag pushed without being the
one computed all produce no error -- tags just quietly stop appearing, or
appear wrong.

Behavioural guards extract the step script from the YAML and run it against
a real repo and a real bare remote. Substring assertions on YAML were
defeated in hate_crack by replacing the whole if/else with an unconditional
push while every test still passed."
```

---
### Task 7: Documentation

> **Design change, 2026-08-26 (supersedes this task's original form).** Tagging
> lives in a `tag` job inside `.github/workflows/ci.yml`, gated on `needs`, not
> in separate `workflow_run`-triggered workflows. `auto-tag.yml` and
> `nightly-tag.yml` do not exist. Do not document them.

**Files:**
- Modify: `README.md` (Usage section, after the `--cleanup` block ending ~line 190)
- Modify: `CLAUDE.md` (new section after "Operator Path Resolution")

**Interfaces:** none.

- [ ] **Step 1: Document the flags and the config key in `README.md`**

After the `--cleanup` block (~line 190) and before `## Where Files Live`, add:

````markdown
To print the installed version:

```bash
spoonmap --version
```

The version comes from the installed package's metadata, which is derived from
the repository's git tags at build time. Running `./spoonmap.py` directly from a
clone installs nothing, so that prints `unknown (running from source)` — which
is expected, not an error.

To check whether a newer release exists:

```bash
./spoonmap.py --check-update
```

**SpooNMAP never checks for updates on its own.** It makes no network connection
other than the scan itself unless you explicitly opt in, because it is routinely
run from jumpboxes inside client networks where an unprompted call out to
`api.github.com` is unwanted traffic from an engagement host. `--check-update`
performs a single check on demand. To enable the check at every startup, set
`"check_for_updates": true` in `config.json`; the key defaults to `false` and
omitting it entirely means `false`. Only stable releases are reported —
nightly release candidates are never advertised as updates.
````

Also add `check_for_updates` to the `## config.json Parameters` section (~line
244), matching the surrounding format: default `false`, "Contact api.github.com
at startup to check for a newer release. Off unless set; see `--check-update`
for a one-off check."

- [ ] **Step 2: Document the release process in `CLAUDE.md`**

Add a section after "Operator Path Resolution":

```markdown
## Release Versioning

Versions are tags, not a string in a file. `pyproject.toml` has no `version`;
hatch-vcs derives it from `git describe`, so `importlib.metadata.version('spoonmap')`
— what `--version` prints — is whatever tag the artifact was built from.

Tags are cut by CI, from the commits themselves. `tools/next_version.py` owns the
entire policy: any `feat:` commit (or a `!` subject, or a `BREAKING CHANGE:`
footer) since the last final tag takes the batch to `X.(Y+1).0`; a batch of only
fixes, docs and chores takes it to `X.Y.(Z+1)`. **The major is never bumped
automatically** — a breaking marker counts as a feature, because an automatic
major is an irreversible published mistake waiting for one mistyped subject
line. Push a major by hand and `release.yml` will publish it.

`nightly` cuts candidates for the version the batch is heading toward
(`v0.1.0rc1`, `v0.1.0rc2`, …) and `main` promotes that same target to its final
release. Aiming candidates one version *forward* is what makes them sort
correctly: `0.0.0 < 0.1.0rc1 < 0.1.0 < 0.2.0rc1 < 0.2.0`. This makes conventional
commit subjects load-bearing — a `feat:` typo'd as `fix:` ships as a patch.

The tagging lives in a `tag` job **inside `ci.yml`**, gated on
`needs: [test, test-legacy, lint, bandit, nse-root, workflow-lint, build]` and
on `github.event_name == 'push'` for `main`/`nightly` only. It is deliberately
not a separate `workflow_run`-triggered workflow, which is how this was first
built: zizmor — a required job in this same file — rates `workflow_run` an
error-level dangerous trigger and exits 14, because it is the standard
privilege-escalation vector, and this repo does not silence findings with ignore
comments. Being a `needs` dependent buys the same "only tag what passed CI"
guarantee without the trigger, and without checking out an explicitly-passed
head SHA. Do not reintroduce `workflow_run` here.

Things that fail silently rather than loudly, all guarded by
`tests/test_release_versioning.py`:

- **`ci.yml` must run on pushes to `nightly`.** Otherwise the tag job never runs
  there and no candidate is ever cut, with no error anywhere.
- **The `tag` job must keep every validating job in `needs`.** Drop one and a
  tag can land on a commit that failed it.
- **`fetch-depth: 0` on both the `tag` and `build` jobs.** The baseline is the
  highest final tag; a shallow clone sees none and computes from 0.0.0, handing
  out a version that already shipped. Verified: a depth-1 clone does not fail —
  it silently versions from no tag at all.
- **The `tag` job sets `persist-credentials: true`**, against this repo's
  convention everywhere else, because it pushes a tag. It is also the only job
  with `contents: write`. That exception is commented at the site and pinned by
  a test; do not "fix" it.

Version arithmetic belongs in `tools/next_version.py`, where it is unit-tested,
never in a workflow step. hate_crack carried ~70 lines of `cut -d.` duplicated
across two YAML files before extracting this module; do not reintroduce it here.

## Update Checking

`check_for_updates` in `config.json` defaults to **false**, and an absent key
means false. It is the only thing that can cause a network connection at startup.
hate_crack's equivalent defaults to true; that is deliberately inverted here,
because SpooNMAP runs from jumpboxes inside client networks where an unprompted
call to `api.github.com` is an unauthorised outbound beacon from an engagement
host. `--check-update` is the on-demand path and ignores the config.

The gate lives in `_maybe_check_for_updates()` rather than inline in `main()`
specifically so it can be tested — `main()` is under `pragma: no cover`, and
"does a default config reach the network" is the one question here that must not
go untested. Its test patches `urllib.request.urlopen` to raise if it is called
at all. `_check_for_updates()` swallows every failure: a courtesy check must
never delay, prompt, or abort a scan. An unknown local version (running from a
checkout) reports the latest release but never claims an update is available.
```

- [ ] **Step 3: Verify the docs match reality**

Re-read both edits against the code as it now stands. Every flag named must
exist, every default stated must be the actual default, every path referenced
must resolve, and no workflow file is named that does not exist. Check
specifically that `--version`, `--check-update`, and `check_for_updates` are
spelled exactly as implemented in Tasks 4 and 5, and that the `needs` list
quoted above matches `ci.yml` exactly.

- [ ] **Step 4: Final full verification**

```bash
cd /tmp/spoonmap-auto-versioning
uv run pytest tests/ -q
uv run --frozen ruff check spoonmap.py tests/ tools/
uv run --frozen bandit -r spoonmap.py -c pyproject.toml -b .bandit-baseline.json
uv lock --check
uvx --from "actionlint-py==1.7.12.24" actionlint > /tmp/al.out 2>&1; echo "actionlint exit=$?"
uvx zizmor==1.29.0 --persona=regular .github/workflows/ > /tmp/zz.out 2>&1; echo "zizmor exit=$?"
git status --short
```
Expected: suite green at or above 95% coverage, lint and SAST clean, lock
current, both workflow linters exiting 0, no unintended files. Capture each exit
code on its own line as shown — a pipeline would report the exit status of the
last command in the pipe, not the linter's.

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document release versioning and opt-in update checking

Records what fails silently rather than loudly -- the nightly CI trigger,
the tag job's needs list, fetch-depth on two jobs, and the
persist-credentials exception -- since each produces no error, just tags
that quietly stop appearing or appear wrong.

Also records why tagging is a needs-gated job rather than a workflow_run
workflow, so the rejected design is not reintroduced by someone reading
the upstream project it was ported from."
```

---
## Post-Implementation Notes

Two consequences to expect on the first real run, both intended and both already
recorded in the spec:

1. **The first `nightly` push treats the entire history as one batch**, since
   there is no baseline tag to bound it. If any commit in that history says
   `feat:`, the first candidate is `v0.1.0rc1` rather than `v0.0.1rc1`. Task 3
   Step 6 tells you which it will be before you push.
2. **Early releases read as `v0.0.x`.** That was chosen deliberately; a human can
   push `v1.0.0` by hand whenever that stops being the right description, and the
   policy builds on it from there.
