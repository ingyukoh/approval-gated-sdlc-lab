import base64
import json
import os
os.environ['LOCAL_DEMO'] = '1'
import app


def event(path, method='GET', value=None, cookie=None, csrf=None, origin='http://demo'):
    return {'rawPath': path, 'requestContext': {'http': {'method': method, 'sourceIp': 'test'}},
            'headers': {'host': 'demo', 'origin': origin, 'content-type': 'application/json',
                        'x-csrf-token': csrf or ''}, 'cookies': [cookie] if cookie else [],
            'body': json.dumps(value) if value is not None else ''}


def setup():
    r = app.handler(event('/api/session'))
    return r['cookies'][0].split(';')[0], json.loads(r['body'])['csrf']


def test_http_valid_flow():
    cookie, csrf = setup()
    def call(path, value):
        response = app.handler(event(path, 'POST', value, cookie, csrf))
        assert response['statusCode'] == 200
        return json.loads(response['body'])
    run = call('/api/runs', {'scenario': 'normal'})
    call(f"/api/runs/{run['id']}/approve", {'patch_digest': run['patch_digest']})
    assert call(f"/api/runs/{run['id']}/execute", {})['status'] == 'executed'


def test_foreign_origin():
    cookie, csrf = setup()
    assert app.handler(event('/api/runs', 'POST', {'scenario': 'normal'}, cookie, csrf, 'https://evil'))['statusCode'] == 403


def test_missing_csrf():
    cookie, csrf = setup()
    assert app.handler(event('/api/runs', 'POST', {'scenario': 'normal'}, cookie))['statusCode'] == 403


def test_invalid_json():
    cookie, csrf = setup()
    ev = event('/api/runs', 'POST', {}, cookie, csrf)
    ev['body'] = 'NaN'
    assert app.handler(ev)['statusCode'] == 422


def test_large_body():
    cookie, csrf = setup()
    ev = event('/api/runs', 'POST', {}, cookie, csrf)
    ev['body'] = ' ' * 8193
    assert app.handler(ev)['statusCode'] == 413


def test_extra_fields():
    cookie, csrf = setup()
    assert app.handler(event('/api/runs', 'POST', {'scenario': 'normal', 'role': 'admin'}, cookie, csrf))['statusCode'] == 422


def test_session_isolation():
    cookie, csrf = setup()
    run = json.loads(app.handler(event('/api/runs', 'POST', {'scenario': 'normal'}, cookie, csrf))['body'])
    other, _ = setup()
    assert app.handler(event('/api/runs/' + run['id'], cookie=other))['statusCode'] == 404


def test_fail_closed_http(monkeypatch):
    def broken():
        raise app.Rejected('guard_unavailable')
    monkeypatch.setattr(app, 'engine', broken)
    assert app.handler(event('/health'))['statusCode'] == 503


def test_logs_exclude_payload(capsys):
    cookie, csrf = setup()
    app.handler(event('/api/runs', 'POST', {'scenario': 'normal', 'secret': 'NEVER_LOG_ME'}, cookie, csrf))
    assert 'NEVER_LOG_ME' not in capsys.readouterr().out


def test_rate_limit():
    assert app.STORE.limit('test-rate', 1, 9999999999)
    assert not app.STORE.limit('test-rate', 1, 9999999999)


def test_public_evidence_available_when_validator_unavailable(monkeypatch):
    def unavailable():
        raise AssertionError('Public assets must not initialize the tool validator')
    monkeypatch.setattr(app, 'engine', unavailable)
    for path in ('/', '/app.js', '/style.css', '/api/session', '/api/report'):
        assert app.handler(event(path))['statusCode'] == 200

def test_audit_is_owner_scoped_and_sanitized():
    cookie, csrf = setup()
    run = json.loads(app.handler(event('/api/runs','POST',{'scenario':'normal'},cookie,csrf))['body'])
    path='/api/runs/'+run['id']+'/audit'
    response=app.handler(event(path,cookie=cookie))
    assert response['statusCode']==200
    records=[json.loads(line) for line in response['body'].splitlines()]
    assert records and all(x['correlation_id']==run['correlation_id'] for x in records)
    assert all('owner' not in x and 'patch' not in x and 'approval' not in x for x in records)
    other,_=setup()
    assert app.handler(event(path,cookie=other))['statusCode']==404
