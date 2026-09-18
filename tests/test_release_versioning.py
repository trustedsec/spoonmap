"""Guards on the release-versioning wiring.

The policy itself -- which component moves, and to what -- lives in
tools/next_version.py and is tested in tests/test_next_version.py. Nothing here
re-implements it.

What this file guards is everything around the policy, all of which fails
*silently*:

* The tag job ceasing to depend on the jobs that validate the commit, which
  would let a tag land on a commit that failed its tests.
* The policy module ceasing to be the only thing that produces a version,
  asserted by running the actual Compute tag step and reading back the outputs
  it writes to $GITHUB_OUTPUT, rather than grepping for function calls.
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


def _normalize_yaml_expr(expr):
    """Normalize YAML expression for comparison: collapse whitespace."""
    return re.sub(r'\s+', ' ', expr.strip())


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
    run -- but only for jobs actually listed here.

    Exclude any job whose own `needs` contains 'tag' (e.g., a future publish job).
    """
    ci = _load('ci.yml')
    needs = set(ci['jobs']['tag']['needs'])

    # Helper to normalize job's needs list, handling both list and string forms
    def get_needs_set(job_def):
        job_needs = job_def.get('needs')
        if isinstance(job_needs, str):
            # Normalize string form to list to avoid substring matching
            return {job_needs}
        elif isinstance(job_needs, list):
            return set(job_needs)
        else:
            return set()

    # Exclude jobs that depend on tag (self-referencing jobs like publish)
    validating = {
        j for j in ci['jobs']
        if j != 'tag' and 'tag' not in get_needs_set(ci['jobs'][j])
    }
    missing = validating - needs
    assert not missing, f'tag job does not depend on: {sorted(missing)}'


def test_the_tag_job_never_runs_on_pull_requests():
    """ci.yml also runs on pull_request, where tagging would be actively
    wrong. Assert the entire normalized if expression, not fragments."""
    condition = _job('ci.yml', 'tag')['if']
    normalized = _normalize_yaml_expr(condition)
    # Must assert the full expression to catch && → || mutations
    expected = _normalize_yaml_expr(
        "github.event_name == 'push' && "
        "(github.ref == 'refs/heads/main' || github.ref == 'refs/heads/nightly')"
    )
    assert normalized == expected, f'Expected: {expected}\nGot: {normalized}'


def test_only_the_tag_job_can_write():
    """The workflow is read-only; exactly one job escalates, and only to what
    pushing a tag and cutting a release requires."""
    # Jobs permitted to declare their own `permissions:`. Adding a name here is
    # a deliberate decision to let another job escalate, and it should come with
    # a reason -- `tag` needs contents: write to push a tag and cut a release.
    # A derived rule was tried here and removed: exempting anything that depends
    # on `tag` let a future job grant itself contents: write with nothing
    # tripping, which is the invariant this test exists to hold.
    MAY_DECLARE_PERMISSIONS = {'tag'}

    ci = _load('ci.yml')
    assert ci['permissions'] == {'contents': 'read'}
    assert ci['jobs']['tag']['permissions'] == {'contents': 'write'}
    for job_id, job in ci['jobs'].items():
        if job_id not in MAY_DECLARE_PERMISSIONS:
            assert 'permissions' not in job, job_id


def test_the_tag_job_does_not_cancel_itself():
    """Two pushes landing together would otherwise both compute the same tag.
    Serialize per branch instead of cancelling, so no push is skipped."""
    concurrency = _job('ci.yml', 'tag')['concurrency']
    assert concurrency['cancel-in-progress'] is False


def test_tag_job_concurrency_group_is_branch_specific():
    """The tag job's concurrency group must not collide with the workflow-level
    group, which would deadlock the job against itself. It must also interpolate
    github.ref to serialize by branch."""
    tag_job = _job('ci.yml', 'tag')
    tag_concurrency_group = tag_job['concurrency']['group']
    workflow_concurrency_group = _load('ci.yml')['concurrency']['group']

    # Groups must be different to avoid deadlock
    assert tag_concurrency_group != workflow_concurrency_group
    # Tag group must reference github.ref to serialize by branch
    assert 'github.ref' in tag_concurrency_group


def test_all_jobs_declare_timeout_minutes():
    """Every job must declare timeout-minutes to bound execution. A hung job
    holding contents: write is the worst one to lose that bound."""
    ci = _load('ci.yml')
    for job_id, job in ci['jobs'].items():
        assert 'timeout-minutes' in job, f'job {job_id} missing timeout-minutes'


# --- checkout depth ----------------------------------------------------------


@pytest.mark.parametrize('job_id', ['tag', 'build'])
def test_version_deriving_jobs_fetch_all_history(job_id):
    """Both jobs derive a version from git describe. A shallow clone does not
    fail either of them -- it silently computes from a baseline of no tags,
    which is how a wrong version ships without anything going red. GitHub
    coerces fetch-depth to a string, so compare as string."""
    depth = _checkout(_job('ci.yml', job_id))['with']['fetch-depth']
    assert str(depth).lower() == '0', f'job {job_id} must have fetch-depth: 0, got {depth}'


def test_the_tag_job_keeps_its_credentials():
    """Deliberate exception to this repo's persist-credentials: false rule:
    this job pushes a tag and needs the token. GitHub coerces to string."""
    persist = _checkout(_job('ci.yml', 'tag'))['with']['persist-credentials']
    assert str(persist).lower() == 'true'


def test_every_other_checkout_drops_its_credentials():
    """All other jobs, in EVERY workflow file, must drop credentials -- not
    just ci.yml's. release.yml also declares `contents: write` (for `gh
    release create`) and is the other place a checkout could quietly gain a
    push-capable token. `tag` (in ci.yml) is the single documented exception:
    it is the only job anywhere that pushes a tag."""
    seen_files = set()
    for filename in os.listdir(WORKFLOWS):
        if not filename.endswith(('.yml', '.yaml')):
            continue
        seen_files.add(filename)
        workflow = _load(filename)
        for job_id, job in workflow['jobs'].items():
            if filename == 'ci.yml' and job_id == 'tag':
                continue
            persist = _checkout(job)['with']['persist-credentials']
            assert str(persist).lower() == 'false', f'{filename}:{job_id}'

    # A floor: the loop above passes vacuously if os.listdir() ever returned
    # only one workflow file (e.g. a filesystem glitch, or a future rename
    # that no longer matches .yml/.yaml). Assert both files this test exists
    # to cover were actually visited.
    assert {'ci.yml', 'release.yml'} <= seen_files, seen_files


# --- the policy module is the only thing that produces a version -------------


def test_exactly_one_call_to_the_policy_module():
    """The policy module must be called exactly once to produce the version.
    Count against the parsed run bodies of the tag job's steps, not the whole
    file (which may contain --repo-dir in comments)."""
    job = _job('ci.yml', 'tag')
    calls = sum(
        len(re.findall(r'tools/next_version\.py\s+--channel', step.get('run', '')))
        for step in job['steps']
    )
    assert calls == 1, f'expected exactly one call to tools/next_version.py, found {calls}'


def test_both_channels_are_reachable():
    """main cuts the final release, nightly cuts a candidate for the same
    target. A job that only ever computed one channel would silently tag
    nightly builds as releases, or never cut a release at all."""
    script = _step_script(_job('ci.yml', 'tag'), 'Compute tag')
    assert 'channel=stable' in script
    assert 'channel=nightly' in script


@pytest.mark.parametrize('branch,expected_channel', [
    ('refs/heads/main', 'stable'),
    ('refs/heads/nightly', 'nightly'),
])
def test_compute_tag_step_assigns_correct_channel(branch, expected_channel, tmp_path):
    """The Compute tag step must actually WRITE the channel and new_tag outputs
    to $GITHUB_OUTPUT. Runs the step in isolation with a real bash subprocess."""
    script = _step_script(_job('ci.yml', 'tag'), 'Compute tag')

    # Minimal environment: only PATH, HOME, and the variables the step needs
    env = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'HOME': os.environ.get('HOME', '/tmp'),
        'GITHUB_REF': branch,
        'GITHUB_OUTPUT': str(tmp_path / 'github_output'),
    }

    result = subprocess.run(
        ['bash', '-c', script],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f'Compute tag step failed: {result.stderr}'

    # Parse the $GITHUB_OUTPUT file to read back the values the step wrote
    output_file = tmp_path / 'github_output'
    assert output_file.exists(), 'Compute tag step did not write $GITHUB_OUTPUT'

    output_contents = output_file.read_text()
    parsed = {}
    for line in output_contents.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            parsed[key] = value

    # Assert the channel is assigned correctly
    assert 'channel' in parsed, f'channel key not in GITHUB_OUTPUT: {parsed}'
    assert parsed['channel'] == expected_channel, \
        f'Expected channel={expected_channel}, got channel={parsed["channel"]}'

    # Assert both keys are present unconditionally. This catches key renames
    # (e.g., echo "new_tag=$new_tag" renamed to echo "tagname=$new_tag").
    assert 'new_tag' in parsed, f'new_tag key not in GITHUB_OUTPUT: {parsed}'
    assert 'channel' in parsed, f'channel key not in GITHUB_OUTPUT (checked twice): {parsed}'

    # Validate new_tag value shape without guarding. Empty is legitimate when HEAD
    # sits exactly on a tag (no new commits). Non-empty must match the channel's
    # tag format: stable uses v0.1.0, nightly uses v0.1.0rc1.
    new_tag = parsed['new_tag']
    if expected_channel == 'stable':
        tag_pattern = r'^v\d+\.\d+\.\d+$'
    else:  # nightly
        tag_pattern = r'^v\d+\.\d+\.\d+rc\d+$'

    # Assert value is either empty or matches the channel-appropriate format.
    # No if guards — validation always runs unconditionally.
    is_empty = new_tag == ''
    matches_pattern = re.match(tag_pattern, new_tag) is not None
    assert is_empty or matches_pattern, \
        f'new_tag must be empty or match {tag_pattern}, got: {new_tag!r}'

    # Count key occurrences in raw file. Mutations that write then blank create a
    # duplicate key line (echo "new_tag=" appended after the real write). This
    # catches the mutation even when the value is legitimately empty.
    new_tag_count = output_contents.count('new_tag=')
    channel_count = output_contents.count('channel=')
    assert new_tag_count == 1, \
        f'new_tag key appears {new_tag_count} times (expected 1): {output_contents!r}'
    assert channel_count == 1, \
        f'channel key appears {channel_count} times (expected 1): {output_contents!r}'


def test_the_pushed_tag_is_the_one_the_policy_computed():
    """The Create tag step must use the tag computed by Compute tag step."""
    job = _job('ci.yml', 'tag')
    compute = [s for s in job['steps'] if 'next_version.py' in s.get('run', '')]
    assert len(compute) == 1
    step_id = compute[0]['id']
    create = [s for s in job['steps'] if s.get('name') == 'Create tag'][0]
    assert create['env']['NEW_TAG'] == '${{ steps.%s.outputs.new_tag }}' % step_id


def test_no_shell_version_arithmetic():
    """Second line of defence. Version math in YAML cannot be unit-tested,
    which is the entire reason tools/next_version.py exists. Scope to tag job
    steps only, not the whole file."""
    job = _job('ci.yml', 'tag')
    script = '\n'.join(step.get('run', '') for step in job['steps'])
    for banned in ('cut -d.', '$((', 'awk -F.'):
        assert banned not in script, f'version arithmetic in tag job: {banned}'


def test_only_stable_publishes_a_release():
    """Nightly candidates exist to make builds addressable, not to be releases.
    Publishing them would make anything ranking releases see a candidate as
    latest. Assert the full if condition, not fragments."""
    release_steps = [
        s for s in _job('ci.yml', 'tag')['steps']
        if s.get('name') == 'Create GitHub release'
    ]
    assert len(release_steps) == 1
    release_step = release_steps[0]

    # Assert the full if condition to catch || true appending
    if_condition = release_step.get('if', '')
    normalized = _normalize_yaml_expr(if_condition)
    assert normalized == _normalize_yaml_expr("steps.bump.outputs.channel == 'stable'"), \
        f'release step if condition must be exactly "steps.bump.outputs.channel == \'stable\'", got: {normalized}'


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
    """Run the Create tag step with minimal environment (no inherited vars)."""
    env = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'HOME': os.environ.get('HOME', '/tmp'),
        'NEW_TAG': new_tag,
    }
    return subprocess.run(
        ['bash', '-c', script], cwd=repo, env=env,
        capture_output=True, text=True,
    )


def test_create_tag_pushes_the_tag(repo_with_remote):
    repo, remote = repo_with_remote
    branches_before = set(_git(remote, 'branch').split())
    script = _step_script(_job('ci.yml', 'tag'), 'Create tag')
    result = _run_create_tag(repo, script, 'v0.1.0')
    assert result.returncode == 0, result.stderr
    assert 'v0.1.0' in _git(remote, 'tag')

    # The step must push ONLY the tag. `git push origin "refs/tags/$NEW_TAG"`
    # mutated to add `HEAD:main` (or to `git push origin --tags`, which would
    # also push any branch refs the local repo happens to carry) would leave
    # the tag assertion above passing while silently also moving/creating a
    # branch on the remote -- something this job has no business doing; only
    # main and nightly themselves are supposed to advance, and only by a real
    # merge, never by this tagging step.
    branches_after = set(_git(remote, 'branch').split())
    assert branches_after == branches_before, (
        f'Create tag step changed the remote branch set: '
        f'before={branches_before}, after={branches_after}'
    )


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


def test_the_release_workflow_uses_only_built_in_actions():
    """The runner already ships gh, and the tag job publishes the same way.
    Assert positive: the release step must call `gh release create`, and no
    step may use a third-party action."""
    job = list(_load('release.yml')['jobs'].values())[0]

    # Positive assertion: at least one step must run gh release create
    gh_found = False
    for step in job['steps']:
        if 'gh release create' in step.get('run', ''):
            gh_found = True
            break
    assert gh_found, 'no step runs `gh release create`'

    # Every step that uses an action must use built-in actions/
    for step in job['steps']:
        uses = step.get('uses', '')
        if uses:
            assert uses.startswith('actions/'), \
                f'release workflow uses non-built-in action: {uses}'


# --- lint job scope -----------------------------------------------------


def test_ruff_covers_every_python_source_directory():
    """The lint job's ruff invocation must check spoonmap.py, tests/, AND
    tools/. tools/next_version.py ships this repo's release-versioning policy
    and is exercised by tests/test_next_version.py just like spoonmap.py
    itself; dropping `tools/` from the ruff command leaves 24 tests passing
    with nothing checking it."""
    script = _step_script(_job('ci.yml', 'lint'), 'Ruff')
    assert re.search(r'\bruff\s+check\b', script), script
    for target in ('spoonmap.py', 'tests/', 'tools/'):
        assert re.search(r'(?<![\w./])' + re.escape(target) + r'(?!\S)', script), \
            f'ruff invocation is missing target {target!r}: {script!r}'
