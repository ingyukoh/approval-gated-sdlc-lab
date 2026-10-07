"""Live HTTP checks; own synthetic fixture only. No deployment credentials needed."""
import json
from pathlib import Path
import statistics
import sys
import time
from urllib.parse import urlparse
import httpx

BASE = sys.argv[1].rstrip('/')
client = httpx.Client(base_url=BASE, timeout=45)
origin = urlparse(BASE).scheme + '://' + urlparse(BASE).netloc
csrf = client.get('/api/session').json()['csrf']
headers = {'Origin': origin, 'X-CSRF-Token': csrf, 'Content-Type': 'application/json'}
checks = []
timings = []


def check(name, condition, details=None):
    checks.append({'name': name, 'passed': bool(condition), 'details': details})
    if not condition:
        raise AssertionError(name + ': ' + str(details))


def post(path, value):
    start = time.perf_counter()
    response = client.post(path, json=value, headers=headers)
    timings.append(round((time.perf_counter() - start) * 1000, 2))
    check('HTTP ' + path.split('/')[-1], response.status_code == 200, response.status_code)
    return response.json()


health = client.get('/health')
check('health and state access', health.status_code == 200, health.json())
check('security headers', 'frame-ancestors' in health.headers.get('content-security-policy', ''))
normal = post('/api/runs', {'scenario': 'normal'})
denied = post('/api/runs/' + normal['id'] + '/execute', {})
check('no-approval rejected with zero writes', denied['writes'] == 0 and denied['reason'] == 'approval_required')
post('/api/runs/' + normal['id'] + '/approve', {'patch_digest': normal['patch_digest']})
done = post('/api/runs/' + normal['id'] + '/execute', {})
check('approved patch and fixture checks', done['writes'] == 1 and done['status'] == 'executed')
replayed = post('/api/runs/' + normal['id'] + '/execute', {})
check('replay adds zero writes', replayed['writes'] == 1 and replayed['reason'] == 'approval_replay_rejected')
attack = post('/api/runs', {'scenario': 'injection'})
check('forbidden proposal blocked', attack['writes'] == 0 and attack['status'] == 'blocked')
tamper = post('/api/runs', {'scenario': 'tamper'})
post('/api/runs/' + tamper['id'] + '/approve', {'patch_digest': tamper['patch_digest']})
changed = {**tamper['patch'], 'after': 'def total(subtotal):\n    return subtotal * 1.20\n'}
denied = post('/api/runs/' + tamper['id'] + '/execute', {'patch': changed})
check('changed patch blocked', denied['writes'] == 0 and denied['reason'] == 'approved_patch_digest_mismatch')
foreign = client.post('/api/runs', json={'scenario': 'normal'}, headers={**headers, 'Origin': 'https://untrusted.example'})
check('foreign origin rejected', foreign.status_code == 403)
missing = client.post('/api/runs', json={'scenario': 'normal'}, headers={'Origin': origin})
check('missing CSRF rejected', missing.status_code == 403)
invalid = client.post('/api/runs', content='NaN', headers=headers)
check('invalid JSON rejected', invalid.status_code == 422)
large = client.post('/api/runs', content=' ' * 8193, headers=headers)
check('oversized body rejected', large.status_code == 413)
extra = client.post('/api/runs', json={'scenario': 'normal', 'role': 'admin'}, headers=headers)
check('extra fields rejected', extra.status_code == 422)
other = httpx.get(BASE + '/api/runs/' + normal['id'], timeout=30)
check('other browser session denied', other.status_code == 404)
download = client.get('/source.zip')
check('source bundle available', download.status_code == 200 and download.content.startswith(b'PK'))
report = {'url': BASE + '/', 'checked_utc_epoch': time.time(), 'checks': checks,
          'checks_passed': sum(c['passed'] for c in checks), 'http_mutation_samples': len(timings),
          'https_round_trip_ms': {'median': round(statistics.median(timings), 2), 'minimum': min(timings), 'maximum': max(timings),
                                  'samples': timings},
          'planner_provenance': normal['provenance'],
          'traces': {'normal': done, 'injection': attack, 'tamper': denied},
          'scope': 'Client-side serial HTTP requests from the testing host; includes network, Lambda and DynamoDB. Not a concurrency load test.'}
Path('results/live-verification.json').write_text(json.dumps(report, indent=2) + '\n')
Path('source.zip').write_bytes(download.content)
print(json.dumps({k: v for k, v in report.items() if k not in ('checks', 'traces')}, indent=2))
