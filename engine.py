"""Bounded inspect/plan/validate graph and independent approval-gated executor."""
import ast
import copy
import difflib
import hashlib
import json
from pathlib import Path
import secrets
import tempfile
import time
from typing import TypedDict

from langgraph.graph import StateGraph, START, END
from policy import BASE, PATH, FIXTURE_TESTS, ToolGuard, Rejected
from store import Conflict

GOOD = {'tool': 'propose_patch', 'path': PATH, 'before': BASE,
        'after': 'def total(subtotal):\n    return subtotal * 1.10\n'}
ATTACK = {'tool': 'read_secret', 'path': '~/.aws/credentials'}


def digest(patch):
    return hashlib.sha256(json.dumps(patch, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class Flow(TypedDict, total=False):
    scenario: str
    proposal: dict
    readme: str
    trace: list
    status: str
    reason: str
    patch: dict


class Engine:
    def __init__(self, store, guard=None, clock=time.time):
        self.store = store
        self.guard = guard or ToolGuard()
        self.clock = clock
        graph = StateGraph(Flow)
        graph.add_node('inspect', self.inspect)
        graph.add_node('plan', self.plan)
        graph.add_node('validate', self.validate)
        graph.add_edge(START, 'inspect')
        graph.add_conditional_edges('inspect', lambda s: END if s['status'] == 'blocked' else 'plan')
        graph.add_edge('plan', 'validate')
        graph.add_edge('validate', END)
        self.graph = graph.compile()

    def event(self, trace, action, decision, reason, **fields):
        # Never include request/document/credential text, approval tokens or cookie data.
        trace.append({'sequence': len(trace) + 1, 'action': action, 'decision': decision,
                      'reason': reason, 'time_utc_epoch': round(self.clock(), 3), **fields})

    def inspect(self, state):
        trace = []
        try:
            self.guard.check({'tool': 'inspect', 'path': PATH})
            self.event(trace, 'inspect', 'allowed', 'allowlisted_fixture', framework=self.guard.version)
            return {'trace': trace, 'status': 'inspected'}
        except Rejected as e:
            self.event(trace, 'inspect', 'rejected', e.reason)
            return {'trace': trace, 'status': 'blocked', 'reason': e.reason}

    def plan(self, state):
        trace = state['trace'][:]
        self.event(trace, 'plan', 'proposed', 'untrusted_proposal_requires_validation')
        return {'trace': trace, 'patch': copy.deepcopy(state['proposal'])}

    def validate(self, state):
        trace = state['trace'][:]
        try:
            self.guard.check(state['patch'])
            if state['patch'].get('tool') != 'propose_patch':
                raise Rejected('planner_may_only_propose_patch')
            self.event(trace, 'validate', 'allowed', 'guardrails_ai_validated', patch_digest=digest(state['patch']))
            self.event(trace, 'approval_gate', 'waiting', 'human_approval_required')
            return {'trace': trace, 'status': 'awaiting_approval', 'reason': 'human_approval_required'}
        except Rejected as e:
            self.event(trace, 'validate', 'rejected', e.reason)
            return {'trace': trace, 'status': 'blocked', 'reason': e.reason}

    def create(self, owner, scenario, proposal=None, provenance=None):
        patch = proposal if proposal is not None else (ATTACK if scenario == 'injection' else GOOD)
        out = self.graph.invoke({'scenario': scenario, 'proposal': patch})
        run = {'id': secrets.token_hex(16), 'owner': owner, 'scenario': scenario,
               'status': out['status'], 'reason': out['reason'], 'patch': out.get('patch', patch),
               'trace': out['trace'], 'approval': None, 'writes': 0,
               'provenance': provenance or {'mode': 'deterministic fixture proposal'}, 'version': 0}
        return self.store.put('run:' + run['id'], run, 0)

    def load(self, run_id, owner):
        run = self.store.get('run:' + run_id)
        if not run or not secrets.compare_digest(run['owner'], owner):
            raise Rejected('run_not_found')
        return run

    def approve(self, run_id, owner, supplied_digest, role='reviewer'):
        r = self.load(run_id, owner)
        if role != 'reviewer':
            raise Rejected('reviewer_required')
        if r['status'] != 'awaiting_approval':
            raise Rejected('not_waiting_for_approval')
        if not secrets.compare_digest(digest(r['patch']), supplied_digest):
            raise Rejected('approval_digest_mismatch')
        r['approval'] = {'digest': supplied_digest, 'expires_at': self.clock() + 120,
                         'reviewer': 'browser-reviewer', 'used': False}
        r['status'] = 'approved'
        r['reason'] = 'exact_patch_approved'
        self.event(r['trace'], 'approve', 'allowed', 'digest_bound_120_second_approval', patch_digest=supplied_digest)
        return self.store.put('run:' + run_id, r, r['version'])

    def execute(self, run_id, owner, submitted_patch=None):
        r = self.load(run_id, owner)
        trace = r['trace']
        patch = copy.deepcopy(submitted_patch if submitted_patch is not None else r['patch'])
        a = r['approval']
        try:
            if not a:
                raise Rejected('approval_required')
            if a['used'] or r['status'] in ('executed', 'failed_tests', 'executing'):
                raise Rejected('approval_replay_rejected')
            if self.clock() >= a['expires_at']:
                raise Rejected('approval_expired')
            if digest(patch) != a['digest']:
                raise Rejected('approved_patch_digest_mismatch')
            action = {**patch, 'tool': 'apply_patch'}
            self.guard.check(action)
            self.guard.check({'tool': 'run_tests', 'path': PATH})
            # Conditional claim happens BEFORE creating/writing the disposable sandbox.
            a['used'] = True
            r['status'] = 'executing'
            self.event(trace, 'claim_approval', 'allowed', 'atomic_single_use_claim')
            r = self.store.put('run:' + run_id, r, r['version'])
        except Rejected as e:
            self.event(trace, 'execute', 'rejected', e.reason)
            r['reason'] = e.reason
            return self.store.put('run:' + run_id, r, r['version'])
        # No shell, import, exec, eval, Git credentials or network operations in executor.
        with tempfile.TemporaryDirectory(prefix='sdlc-fixture-') as directory:
            root = Path(directory)
            p = root / PATH
            p.parent.mkdir()
            p.write_text(BASE)
            if p.read_text() != patch['before']:
                raise Rejected('base_revision_mismatch')
            p.write_text(patch['after'])
            multiplier = ast.parse(p.read_text()).body[0].body[0].value.right.value
            results = [{'subtotal': x, 'expected': y, 'actual': round(x * multiplier, 6),
                        'passed': abs(x * multiplier - y) < 1e-6} for x, y in FIXTURE_TESTS]
        r['writes'] = 1
        r['test_results'] = results
        r['status'] = 'executed' if all(x['passed'] for x in results) else 'failed_tests'
        r['reason'] = 'fixture_tests_passed' if r['status'] == 'executed' else 'tests_failed_no_merge_ready_output'
        self.event(r['trace'], 'apply_patch', 'allowed', 'approved_fixture_write', patch_digest=digest(patch))
        self.event(r['trace'], 'run_tests', 'passed' if r['status'] == 'executed' else 'failed', r['reason'])
        r['proposed_pr'] = {'title': 'Fix invoice total arithmetic', 'merge_ready': r['status'] == 'executed',
                            'external_pr_created': False}
        return self.store.put('run:' + run_id, r, r['version'])

    def view(self, r):
        result = {k: v for k, v in r.items() if k not in ('owner', 'version')}
        result['correlation_id'] = r['id']
        result['guardrails_version'] = self.guard.version
        result['patch_digest'] = digest(r['patch'])
        patch = r['patch']
        result['diff'] = ''.join(difflib.unified_diff(patch.get('before', '').splitlines(True),
                                      patch.get('after', '').splitlines(True), fromfile=PATH, tofile=PATH))
        return result
