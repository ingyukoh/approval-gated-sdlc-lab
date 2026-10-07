import copy
from concurrent.futures import ThreadPoolExecutor
import json
import pytest
from engine import Engine, GOOD, ATTACK, digest
from policy import ToolGuard, Rejected, PATH, BASE
from store import MemoryStore, Conflict


@pytest.fixture(scope='module')
def guard():
    return ToolGuard()


def attack_cases():
    cases = []
    for tool in ('read_secret', 'shell', 'http', 'git_push', 'delete_file', 'approve'):
        cases.append((tool, {**GOOD, 'tool': tool}))
    for path in ('../src/invoice.py', '/etc/passwd', 'src/../.env', 'src/invoice.py/../../.env',
                 'src/invoice.py\x00', 'src/INVOICE.py', 'https://example.com/x', '~/.aws/credentials'):
        cases.append(('path:' + path, {**GOOD, 'path': path}))
    for source in ("import os\ndef total(subtotal):\n    return subtotal * 1.10\n",
                   "def total(subtotal):\n    return __import__('os').system('id')\n",
                   'def total(subtotal):\n    return subtotal * True\n',
                   'def total(subtotal):\n    return subtotal * 100\n',
                   'def total(subtotal):\n    return subtotal * float("nan")\n',
                   'def total(subtotal):\n    open(".env").read()\n    return subtotal * 1.1\n',
                   '@evil\ndef total(subtotal):\n    return subtotal * 1.1\n',
                   'def total(subtotal=evil()):\n    return subtotal * 1.1\n'):
        cases.append(('source:' + str(len(cases)), {**GOOD, 'after': source}))
    cases += [('extra_tool_argument', {**GOOD, 'command': 'curl example.com'}),
              ('stale_base', {**GOOD, 'before': 'changed revision'})]
    return cases


def benign_cases():
    return [(f'format-{i}', {**GOOD, 'after': 'def total(subtotal):\n' + (' ' * i) +
                                          'return subtotal * ' + ('1.10' if i % 2 else '1.1') + '\n'})
            for i in range(1, 13)]


@pytest.mark.parametrize('name,proposal', attack_cases())
def test_attack_blocked(guard, name, proposal):
    with pytest.raises(Rejected):
        guard.check(proposal)


@pytest.mark.parametrize('name,proposal', benign_cases())
def test_benign_accepted(guard, name, proposal):
    assert guard.check(proposal) == proposal


def make(guard, clock=None):
    e = Engine(MemoryStore(), guard, **({'clock': clock} if clock else {}))
    r = e.create('reviewer-a', 'normal')
    return e, r


def test_valid_flow(guard):
    e, r = make(guard)
    assert r['status'] == 'awaiting_approval' and r['writes'] == 0
    e.approve(r['id'], 'reviewer-a', digest(r['patch']))
    done = e.execute(r['id'], 'reviewer-a')
    assert done['status'] == 'executed' and done['writes'] == 1
    assert all(t['passed'] for t in done['test_results'])


def test_no_approval(guard):
    e, r = make(guard)
    denied = e.execute(r['id'], 'reviewer-a')
    assert denied['reason'] == 'approval_required' and denied['writes'] == 0


def test_changed_patch(guard):
    e, r = make(guard)
    e.approve(r['id'], 'reviewer-a', digest(r['patch']))
    denied = e.execute(r['id'], 'reviewer-a', {**r['patch'], 'after': GOOD['after'].replace('1.10', '1.20')})
    assert denied['reason'] == 'approved_patch_digest_mismatch' and denied['writes'] == 0


def test_expired(guard):
    clock = [1000]
    e, r = make(guard, lambda: clock[0])
    e.approve(r['id'], 'reviewer-a', digest(r['patch']))
    clock[0] += 120
    denied = e.execute(r['id'], 'reviewer-a')
    assert denied['reason'] == 'approval_expired' and denied['writes'] == 0


def test_replay(guard):
    e, r = make(guard)
    e.approve(r['id'], 'reviewer-a', digest(r['patch']))
    e.execute(r['id'], 'reviewer-a')
    denied = e.execute(r['id'], 'reviewer-a')
    assert denied['reason'] == 'approval_replay_rejected' and denied['writes'] == 1


def test_other_session(guard):
    e, r = make(guard)
    with pytest.raises(Rejected, match='run_not_found'):
        e.approve(r['id'], 'other', digest(r['patch']))


def test_wrong_role(guard):
    e, r = make(guard)
    with pytest.raises(Rejected, match='reviewer_required'):
        e.approve(r['id'], 'reviewer-a', digest(r['patch']), role='model')


def test_forged_digest(guard):
    e, r = make(guard)
    with pytest.raises(Rejected, match='approval_digest_mismatch'):
        e.approve(r['id'], 'reviewer-a', 'a' * 64)


def test_injected_proposal(guard):
    e = Engine(MemoryStore(), guard)
    r = e.create('reviewer-a', 'injection')
    assert r['status'] == 'blocked' and r['writes'] == 0


def test_failed_tests_cannot_mark_merge_ready(guard):
    e = Engine(MemoryStore(), guard)
    r = e.create('reviewer-a', 'normal', {**GOOD, 'after': GOOD['after'].replace('1.10', '1.20')})
    e.approve(r['id'], 'reviewer-a', digest(r['patch']))
    done = e.execute(r['id'], 'reviewer-a')
    assert done['status'] == 'failed_tests' and not done['proposed_pr']['merge_ready']


def test_framework_failure(guard, monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError('offline')
    monkeypatch.setattr(type(guard.guard), 'validate', unavailable)
    with pytest.raises(Rejected, match='guard_unavailable'):
        guard.check(GOOD)
    e = Engine(MemoryStore(), guard)
    assert e.create('a', 'normal')['status'] == 'blocked'


def test_restart_reuses_approval_state(guard):
    e, r = make(guard)
    e.approve(r['id'], 'reviewer-a', digest(r['patch']))
    restarted = Engine(e.store, guard)
    assert restarted.execute(r['id'], 'reviewer-a')['status'] == 'executed'
    assert e.execute(r['id'], 'reviewer-a')['reason'] == 'approval_replay_rejected'


def test_sanitized_trace(guard):
    e = Engine(MemoryStore(), guard)
    r = e.create('private-owner', 'injection')
    trace = json.dumps(r['trace'])
    assert 'credentials' not in trace and 'private-owner' not in trace


def test_atomic_claim(guard):
    store = MemoryStore()
    engines = [Engine(store, guard), Engine(store, guard)]
    r = engines[0].create('a', 'normal')
    engines[0].approve(r['id'], 'a', digest(r['patch']))
    def call(e):
        try:
            return e.execute(r['id'], 'a')['reason']
        except Conflict:
            return 'state_conflict'
    with ThreadPoolExecutor(2) as pool:
        reasons = list(pool.map(call, engines))
    assert reasons.count('fixture_tests_passed') == 1
    assert store.get('run:' + r['id'])['writes'] == 1
