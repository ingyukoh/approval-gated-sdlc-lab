"""Authored structural corpus, not a benchmark of the planner's attack resistance."""
import json
from pathlib import Path
import statistics
import time
from policy import ToolGuard, Rejected
from tests.test_boundaries import attack_cases, benign_cases


def main():
    guard = ToolGuard()
    rows = []
    for kind, cases in [('attack', attack_cases()), ('benign', benign_cases())]:
        for name, proposal in cases:
            start = time.perf_counter()
            reason = None
            try:
                guard.check(proposal)
            except Rejected as error:
                reason = error.reason
            rows.append({'case': name, 'kind': kind, 'blocked': bool(reason), 'reason': reason,
                         'validation_ms': round((time.perf_counter() - start) * 1000, 3)})
    attacks = [r for r in rows if r['kind'] == 'attack']
    benign = [r for r in rows if r['kind'] == 'benign']
    baseline_accepted = sum(isinstance(p, dict) and isinstance(p.get('tool'), str)
                            and isinstance(p.get('path'), str) for _, p in attack_cases())
    summary = json.loads(Path('results/pytest-summary.json').read_text())
    report = {'date': '2026-10-08', 'guardrails_ai': guard.version,
              'attack_cases': len(attacks), 'attack_blocked': sum(r['blocked'] for r in attacks),
              'benign_cases': len(benign), 'benign_accepted': sum(not r['blocked'] for r in benign),
              'false_rejection_rate': sum(r['blocked'] for r in benign) / len(benign),
              'control_checks': summary['controls'], 'control_checks_passed': summary['controls_passed'],
              'all_pytest_checks': summary,
              'unguarded_schema_only_baseline': {'attack_accepted': baseline_accepted, 'attack_cases': len(attacks),
                                                 'attack_acceptance': f'{baseline_accepted}/{len(attacks)} passed the type-only proposal gate',
                                                 'execution': 'not executed; pass-through proposal acceptance comparator'},
              'validation_median_ms': round(statistics.median(r['validation_ms'] for r in rows), 3),
              'scope': '24 authored forbidden proposals and 12 benign formatting variants; separate approval/HTTP checks. This is a bounded tool-policy evaluation, not an LLM prompt-injection benchmark or production security certification.',
              'cases': rows}
    Path('results/evaluation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}, indent=2))


if __name__ == '__main__':
    main()
