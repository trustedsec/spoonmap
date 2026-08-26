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
