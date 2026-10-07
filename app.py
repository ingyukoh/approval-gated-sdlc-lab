"""Shared HTTP service for Lambda Function URLs and local FastAPI.

No submitted repository text is logged. Public reviewers can touch only fixtures.
"""
import base64
from http.cookies import SimpleCookie
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import resource
import secrets
import sys
import time

from errors import Rejected
from store import MemoryStore, DynamoStore, Conflict

ROOT = Path(__file__).parent
WORKER_ID = secrets.token_hex(8)
KEY = os.getenv('SESSION_KEY', secrets.token_hex(32)).encode()
STORE = DynamoStore(os.environ['STATE_TABLE']) if os.getenv('STATE_TABLE') else MemoryStore()
ENGINE = None
INIT_ERROR = False
HEADERS = {'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
           'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
           'Strict-Transport-Security': 'max-age=31536000', 'Cache-Control': 'no-store'}


def engine():
    global ENGINE, INIT_ERROR
    if ENGINE is None:
        try:
            from engine import Engine
            ENGINE = Engine(STORE)
        except Exception:
            INIT_ERROR = True
            raise Rejected('guard_unavailable') from None
    return ENGINE


def mac(text):
    return hmac.new(KEY, text.encode(), hashlib.sha256).hexdigest()


def session(headers, cookies):
    jar = SimpleCookie()
    try:
        jar.load('; '.join(cookies) or headers.get('cookie', ''))
        value = jar['sdlc_session'].value
        ident, expires, sig = value.split('.')
        body = ident + '.' + expires
        if re.fullmatch('[a-f0-9]{32}', ident) and int(expires) > time.time() and hmac.compare_digest(mac(body), sig):
            return ident, None
    except (KeyError, ValueError, TypeError):
        pass
    ident = secrets.token_hex(16)
    body = ident + '.' + str(int(time.time()) + 3600)
    secure = '' if os.getenv('LOCAL_DEMO') == '1' else '; Secure'
    return ident, f'sdlc_session={body}.{mac(body)}; Path=/; Max-Age=3600; HttpOnly; SameSite=Strict{secure}'


def reply(code, value, cookie=None, content_type='application/json'):
    binary = isinstance(value, bytes)
    result = {'statusCode': code, 'headers': {**HEADERS, 'Content-Type': content_type, 'X-Demo-Worker': WORKER_ID},
              'body': base64.b64encode(value).decode() if binary else json.dumps(value, allow_nan=False),
              'isBase64Encoded': binary}
    if cookie:
        result['cookies'] = [cookie]
    return result


def body(event):
    raw = event.get('body') or ''
    if event.get('isBase64Encoded'):
        raw = base64.b64decode(raw, validate=True).decode()
    if len(raw.encode()) > 8192:
        raise Rejected('body_too_large')
    try:
        value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError):
        raise Rejected('invalid_json') from None
    if not isinstance(value, dict):
        raise Rejected('object_required')
    return value


def exact(value, required, optional=()):
    if not required <= set(value) or set(value) - required - set(optional):
        raise Rejected('invalid_fields')


def handler(event, context=None):
    started = time.perf_counter()
    method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    path = event.get('rawPath', '/')
    headers = {k.lower(): v for k, v in event.get('headers', {}).items()}
    owner, cookie = session(headers, event.get('cookies', []))
    status = 500
    try:
        if method == 'GET':
            ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'local')
            bucket = int(time.time()) // 60
            if not STORE.limit('read:' + mac('ip:' + ip)[:24] + ':' + str(bucket), 100, (bucket + 2) * 60):
                raise Rejected('request_limit')
        assets = {'/': ('static/index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('static/app.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('static/style.css', 'text/css; charset=utf-8'),
                  '/source.zip': ('source.zip', 'application/zip')}
        if method == 'GET' and path in assets:
            file, ct = assets[path]
            result = reply(200, (ROOT / file).read_bytes(), cookie, ct)
        elif method == 'GET' and path == '/api/session':
            result = reply(200, {'csrf': mac('csrf:' + owner), 'reviewer_role': 'public fixture reviewer'}, cookie)
        elif method == 'GET' and path == '/api/report':
            result = reply(200, json.loads((ROOT / 'results/evaluation.json').read_text()), cookie)
        elif method == 'GET' and path in ('/api/delivery', '/api/live-model-report'):
            filename = 'github-delivery.json' if path == '/api/delivery' else 'live-model-evaluation.json'
            file = ROOT / 'results' / filename
            result = reply(200, json.loads(file.read_text()) if file.exists() else {'status': 'not_recorded'}, cookie)
        elif method == 'GET' and path == '/health':
            e = engine()
            STORE.get('health:probe')
            result = reply(200, {'status': 'ok', 'guardrails_ai': e.guard.version,
                                'worker_id': WORKER_ID,
                                'process_peak_rss_mb': round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024 if sys.platform == 'darwin' else 1024), 2),
                                'persistence': 'DynamoDB' if os.getenv('STATE_TABLE') else 'local memory',
                                'planner': 'recorded proposal' if (ROOT / 'results/model-proposal.json').exists() else 'fixture'}, cookie)
        else:
            if method == 'POST':
                if headers.get('origin') != ('http' if os.getenv('LOCAL_DEMO') == '1' else 'https') + '://' + headers.get('host', ''):
                    raise Rejected('origin_rejected')
                if not hmac.compare_digest(headers.get('x-csrf-token', ''), mac('csrf:' + owner)):
                    raise Rejected('csrf_rejected')
                if headers.get('content-type', '').split(';')[0] != 'application/json':
                    raise Rejected('json_content_type_required')
                minute = int(time.time()) // 60
                ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'local')
                iphash = mac('ip:' + ip)[:24]
                checks = [('rate:' + iphash + ':' + str(minute), 30, (minute + 2) * 60),
                          ('day:' + iphash + ':' + str(minute // 1440), 240, (minute // 1440 + 2) * 86400),
                          ('global:' + str(minute // 1440), 2000, (minute // 1440 + 2) * 86400)]
                if not all(STORE.limit(*x) for x in checks):
                    raise Rejected('request_limit')
                v = body(event)
            e = engine()
            if method == 'POST' and path == '/api/runs':
                exact(v, {'scenario'})
                if v['scenario'] not in ('normal', 'injection', 'tamper'):
                    raise Rejected('scenario_not_allowed')
                proposal, provenance = None, None
                recorded = ROOT / 'results/model-proposal.json'
                if v['scenario'] != 'injection' and recorded.exists():
                    data = json.loads(recorded.read_text())
                    proposal, provenance = data['proposal'], data['provenance']
                r = e.create(owner, v['scenario'], proposal, provenance)
                result = reply(200, e.view(r), cookie)
            elif re.fullmatch(r'/api/runs/[a-f0-9]{32}(?:/(approve|execute|audit))?', path):
                run_id = path.split('/')[3]
                if method == 'GET' and path.endswith('/audit'):
                    r = e.load(run_id, owner)
                    records = [{**item, 'correlation_id': r['id']} for item in r['trace']]
                    data = ''.join(json.dumps(item, allow_nan=False) + '\n' for item in records).encode()
                    result = reply(200, data, cookie, 'application/x-ndjson')
                    result['headers']['Content-Disposition'] = 'attachment; filename="sdlc-audit.jsonl"'
                    status = result['statusCode']
                    return result
                if method == 'GET' and len(path.split('/')) == 4:
                    r = e.load(run_id, owner)
                elif method == 'POST' and path.endswith('/approve'):
                    exact(v, {'patch_digest'})
                    if not isinstance(v['patch_digest'], str) or not re.fullmatch('[a-f0-9]{64}', v['patch_digest']):
                        raise Rejected('invalid_digest')
                    r = e.approve(run_id, owner, v['patch_digest'])
                elif method == 'POST' and path.endswith('/execute'):
                    exact(v, set(), ('patch',))
                    if 'patch' in v and not isinstance(v['patch'], dict):
                        raise Rejected('invalid_patch')
                    r = e.execute(run_id, owner, v.get('patch'))
                else:
                    raise Rejected('route_not_found')
                result = reply(200, e.view(r), cookie)
            else:
                raise Rejected('route_not_found')
        status = result['statusCode']
    except Rejected as ex:
        status = {'run_not_found': 404, 'route_not_found': 404, 'request_limit': 429,
                  'guard_unavailable': 503, 'body_too_large': 413, 'origin_rejected': 403,
                  'csrf_rejected': 403}.get(ex.reason, 422)
        result = reply(status, {'error': ex.reason, 'writes': 0}, cookie)
    except Conflict:
        status = 409
        result = reply(status, {'error': 'state_conflict_retry_read'}, cookie)
    except Exception:
        status = 503
        result = reply(status, {'error': 'service_unavailable', 'writes': 0}, cookie)
    # Only route class and counters: never submitted text, cookies, IP, patches or run IDs.
    print(json.dumps({'event': 'http_request', 'method': method if method in ('GET', 'POST') else 'OTHER',
                      'status': status, 'elapsed_ms': round((time.perf_counter() - started) * 1000, 2)}))
    return result


def local_app():
    from fastapi import FastAPI, Request
    from fastapi.responses import Response
    api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @api.api_route('/{rest:path}', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    async def route(request: Request, rest: str):
        raw = await request.body()
        if len(raw) > 8192:
            return Response(json.dumps({'error': 'body_too_large'}), status_code=413, media_type='application/json', headers=HEADERS)
        event = {'rawPath': '/' + rest, 'body': raw.decode(errors='replace'),
                 'headers': dict(request.headers), 'requestContext': {'http': {
                     'method': request.method, 'sourceIp': request.client.host}}}
        result = handler(event)
        data = base64.b64decode(result['body']) if result['isBase64Encoded'] else result['body'].encode()
        response = Response(data, status_code=result['statusCode'], headers=result['headers'])
        for value in result.get('cookies', []):
            response.headers.append('set-cookie', value)
        return response
    return api
