# Auto-versioning for SpooNMAP

Date: 2026-08-26
Status: approved, not yet implemented

## Goal

Give SpooNMAP the tag-driven release versioning that hate_crack uses: CI-gated
tags cut automatically from conventional-commit content, a version that comes
from git rather than a hand-maintained string, and a way for an operator to see
which version they are running. Adapted for SpooNMAP's hatchling build and its
`main` + `nightly` branch pair.

One deliberate divergence from hate_crack, decided up front: **SpooNMAP never
contacts the network at launch unless the operator explicitly turned that on.**
hate_crack's `check_for_updates` config key defaults to `True` and its startup
path calls `check_for_updates()` on every run. SpooNMAP runs from jumpboxes
inside client networks, where an unprompted call to `api.github.com` is an
outbound beacon from an engagement host that nobody authorised. The capability
is ported; the default is inverted and a test holds it there.

## Versioning policy

Ordinary semver, with the bump derived from what is in the batch since the last
final tag:

- Any `feat:` commit (including `feat(scope):`, `feat!:`, or a
  `BREAKING CHANGE:` footer on any type) means the batch targets `X.(Y+1).0`.
- A batch of only fixes, docs and chores targets `X.Y.(Z+1)`.
- The major component is never bumped automatically. A breaking marker counts
  as a feature, not a major. An automatic major is an irreversible published
  mistake waiting for one mistyped subject line, so a major stays an explicit
  human act: tag and push it by hand, which `release.yml` then picks up.

`nightly` cuts release candidates for whichever version the batch is heading
toward — `v0.0.1rc1`, `v0.0.1rc2`, … — and merging down to `main` promotes that
same target to its final release. These are real PEP 440 pre-releases, so they
sort correctly at both ends:

    0.0.0 < 0.0.1rc1 < 0.0.1rc2 < 0.0.1 < 0.1.0rc1 < 0.1.0

The target can change mid-cycle: the first `feat` to land moves it from
`X.Y.(Z+1)` to `X.(Y+1).0`, and candidate numbering restarts for the new target.
That is intended — the number always names what the batch would ship as today.

The baseline is the highest *final* tag in the repository, deliberately not
restricted to tags reachable from HEAD. `main`'s release tag can sit on a commit
the `nightly` tip does not contain, and a reachability-restricted lookup would
compute the next nightly from a stale baseline and hand out a version below the
release that already shipped.

### Starting point

The repository has no tags. The baseline is therefore `(0, 0, 0)`, and no seed
tag is pushed: the first fix-only batch cuts `v0.0.1` and the first batch
containing a feature cuts `v0.1.0`. `pyproject.toml`'s current static
`version = "0.1.0"` is discarded rather than seeded, since the version becomes
derived state (see below) and there is nothing to carry forward.

Two consequences accepted at design time:

1. Early releases read as `v0.0.x` even though the tool is in real engagement
   use. Acceptable; a human can push a `v1.0.0` by hand whenever that stops
   being true, and the policy will build on it from there.
2. The first push to `nightly` after this lands treats the entire history as one
   batch, since there is no baseline tag to bound it. If any commit in that
   history says `feat:`, the first candidate is `v0.1.0rc1` rather than
   `v0.0.1rc1`.

## Components

### 1. `tools/next_version.py`

A port of hate_crack's policy module. Pure functions — `parse_final`,
`latest_final`, `has_feature`, `target_version`, `next_rc_number`, `compute` —
plus a thin git boundary (`git_tags`, `commit_messages`) and a
`--channel stable|nightly` CLI that prints the tag to create, or prints nothing
and exits 0 when there is nothing to tag.

An empty batch returning "no tag" is not an error: a workflow re-run on an
already-tagged commit lands there, and the right answer is silence rather than a
version nobody asked for. This is *not* a "no feat/fix commits, skip" early
exit — a docs-only or chore-only merge is still a release, it just cuts a patch.

The whole point of this file is that the policy lives in Python, where it can be
unit-tested, instead of in YAML, where it cannot. Neither workflow parses or
increments a version number. Additions go here, not into a workflow step.

**Adaptation required for SpooNMAP:** hate_crack's module uses
`Version = tuple[int, int, int]` at module level and `X | None` return
annotations. The alias is a runtime subscript of `tuple` and fails on Python
3.8; SpooNMAP's `test-legacy` CI job runs the whole suite on 3.8 and 3.9, which
collects this module's tests. Use `typing.Tuple` / `typing.Optional` instead, in
both the module and its tests.

### 2. Tagging workflows

Three files under `.github/workflows/`:

- **`nightly-tag.yml`** — `workflow_run` on a successful `CI` run on `nightly`.
  Calls `next_version.py --channel nightly`, pushes `vX.Y.ZrcN`. Creates no
  GitHub release; these tags exist to make nightly builds addressable and to
  give the build backend a version.
- **`auto-tag.yml`** — `workflow_run` on a successful `CI` run on `main`. Calls
  `next_version.py --channel stable`, pushes `vX.Y.Z`, then creates the GitHub
  release with `gh release create --generate-notes`. The release is created here
  rather than left to `release.yml` because GitHub does not dispatch workflow
  events for refs pushed with `GITHUB_TOKEN`, so a tag pushed by this job would
  never trigger a `push: tags:` workflow.
- **`release.yml`** — `push: tags: v*`. The path for tags a human pushes by
  hand, which is what the "no automatic major" rule depends on existing.

Requirements common to both tagging workflows:

- `ref: ${{ github.event.workflow_run.head_sha }}` — `workflow_run` defaults to
  the tip of the default branch, which is not necessarily the commit CI
  validated.
- `fetch-depth: 0` — the version baseline is read from tags. Under a shallow
  clone the project version reads as nothing and the job tags nonsense.
- `concurrency` group with `cancel-in-progress: false` — two merges landing
  back-to-back would otherwise compute the same tag and the second push would
  fail. Serialize rather than cancel so no merge gets skipped.
- Idempotent tag creation: a re-run must not fail the job if the tag or release
  already exists.
- Guard on `workflow_run.conclusion == 'success'` so a broken commit is never
  tagged or released.

**`nightly-tag.yml` must live on `main`.** GitHub only dispatches `workflow_run`
for workflows present on the default branch; a copy existing solely on `nightly`
never fires.

**Credential exception.** SpooNMAP's convention is `persist-credentials: false`
on every checkout. The two tagging jobs push a tag and so must keep credentials
persisted. This is a deliberate, commented exception at each site, not drift.
`release.yml` keeps `persist-credentials: false`, since it only reads.

### 3. `ci.yml` changes

Two edits, both load-bearing:

- **Add `nightly` to the `push` branches.** CI currently runs on `pull_request`
  and `push` to `main` only, so a push to `nightly` runs no CI at all and
  `nightly-tag.yml`'s `workflow_run` trigger would never fire. hate_crack's
  workflow header records hitting exactly this.
- **`fetch-depth: 0` on the `build` job's checkout.** hatch-vcs cannot resolve a
  version from a depth-1 clone with no tags, so `uv build` would fail there.

The existing `workflow-lint` job already runs actionlint and zizmor against the
whole `.github/workflows/` directory, so the three new files are covered with no
edit to that job.

### 4. `pyproject.toml`

- `build-system.requires` gains `hatch-vcs`.
- `version = "0.1.0"` becomes `dynamic = ["version"]`, with
  `[tool.hatch.version] source = "vcs"` and setuptools-scm's `no-guess-dev`
  version scheme and `no-local-version` local scheme, matching hate_crack.
- `tools/` joins the sdist `include` allowlist.
- `pyyaml` joins the `dev` group, for the workflow guard tests.

No commitizen. hate_crack pins it and configures `[tool.commitizen]`, but its
workflows call `next_version.py` and never actually run `cz bump`, so porting it
would add a pinned dependency that nothing executes.

### 5. `--version`

A module-level `_tool_version()` helper in `spoonmap.py` reading
`importlib.metadata.version('spoonmap')`, falling back to a "running from
source" string on `PackageNotFoundError` — the tool is frequently invoked as a
plain script from a checkout, where no distribution metadata exists. Wired into
`main()` beside the existing `--cleanup` dispatch.

The helper lives outside `main()`'s `# pragma: no cover` region so it is
testable directly, the same reasoning that keeps `_operator_dir()` a module-level
function.

### 6. Opt-in update checking

`_check_for_updates()` in `spoonmap.py`: GET
`https://api.github.com/repos/trustedsec/spoonmap/releases/latest`, compare the
tag against `_tool_version()`, print a one-line notice if a newer release
exists.

- **Off unless explicitly enabled.** `_load_config()` gains an optional
  `check_for_updates` key, absent-means-false, and that key is the only way to
  enable the launch-time check. It is not a required key; a config that never
  mentions it is valid and inert. This needs a `_config_bool(key, value,
  default)` helper alongside the existing `_config_int()`, warning and taking
  the default on a non-boolean value.
- **`config.json.sample` ships it explicitly `false`,** so the safe state is
  also the documented one.
- **`--check-update`** performs one check and exits, regardless of config, so an
  operator can ask without leaving the startup check enabled.
- **Stdlib only.** `spoonmap.py` is deliberately dependency-free, so this uses
  `urllib.request` with a short timeout — not `requests` — and a small local
  version-tuple comparison rather than `packaging.parse`. `spoonmap.py` cannot
  import `tools/next_version.py`; that module is build tooling, not a runtime
  dependency, and the wheel ships `spoonmap.py` alone.
- **Every failure is swallowed** into at most a one-line warning. A failed or
  slow update check must never delay, prompt, or abort a scan.
- **An unknown local version is not an update.** When `_tool_version()` returns
  its running-from-source fallback there is nothing to compare against, so the
  check reports the latest release as information and never claims an upgrade is
  available. Guessing "newer" there would nag every operator running from a
  checkout, which is most of them.
- **Nightly RCs stay invisible.** GitHub's `releases/latest` endpoint excludes
  prereleases, so candidate tags are never advertised as updates.

### 7. Documentation

`CLAUDE.md` gains a section covering the release policy, the branch-to-channel
mapping, why `nightly-tag.yml` must live on `main`, the `persist-credentials`
exception, and the opt-in-off-by-default rule for update checking. `README.md`
documents `--version`, `--check-update`, and the `check_for_updates` config key
with its default.

## Testing

- **`tests/test_next_version.py`** — the pure policy: bump selection across
  feat/fix/docs/breaking batches, subject anchoring (a `feat` mentioned
  mid-sentence in a fix body must not promote the batch), RC numbering including
  the target-changed-mid-cycle restart, baseline selection from a mixed tag
  list, and the empty-batch `None`.
- **`tests/test_release_versioning.py`** — the wiring that breaks silently:
  that `ci.yml` pushes on `nightly`; that each tagging workflow calls
  `next_version.py` exactly once and pushes the tag it printed; that no shell
  version arithmetic has crept back in. Following hate_crack's recorded lesson,
  the load-bearing guards (computed tag value, tag idempotency, empty-batch
  path) assert behaviour by extracting the step script from the YAML and running
  it against a real git repository and a real bare remote — substring assertions
  on YAML are sensitive to formatting and blind to behaviour, and a reviewer
  defeated hate_crack's substring version without any test failing.
- **Inert-default guard** — with a config that does not mention
  `check_for_updates`, `urllib.request.urlopen` is patched to raise if called at
  all, so a future change that reintroduces a launch-time network call fails the
  suite instead of shipping. This follows the precedent already recorded in
  `CLAUDE.md` for defaulting a config to something inert and asserting it.
- **`_check_for_updates()` and `_tool_version()`** — the explicit-true path, the
  swallowed-failure path, both branches of the metadata lookup, and the version
  comparison.

The repo's 95% coverage floor and `ruff`/`bandit` gates apply as usual.
`tools/next_version.py` is not under `--cov=spoonmap`, so its tests run without
contributing to that floor; coverage stays scoped to `spoonmap.py`.

## Out of scope

- Publishing to PyPI. hate_crack has a `pypi-placeholder.yml`; SpooNMAP has no
  publish infrastructure and a prototyped hatch build hook was already dropped
  once for that reason.
- Automatic major bumps.
- A `--update` self-update command. hate_crack has one; nothing here needs it,
  and it is a separate decision from knowing an update exists.
- Rewriting `CHANGELOG.md`. Release notes come from
  `gh release --generate-notes`.
