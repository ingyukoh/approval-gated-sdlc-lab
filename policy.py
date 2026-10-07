"""Fail-closed Guardrails AI boundary for every repository/tool operation."""
import ast
import json
import os
from importlib.metadata import version
from errors import Rejected

os.environ.setdefault('OTEL_SDK_DISABLED', 'true')
os.environ.setdefault('GUARDRAILS_PROCESS_COUNT', '1')
os.environ.setdefault('LANGCHAIN_TRACING_V2', 'false')
os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')

from guardrails import Guard
from guardrails.validators import Validator, register_validator, PassResult, FailResult

PATH = 'src/invoice.py'
BASE = 'def total(subtotal):\n    return subtotal * 0.10\n'
FIXTURE_TESTS = [(0.0, 0.0), (100.0, 110.0), (25.5, 28.05)]


def valid_source(source):
    """Accept exactly one arithmetic return over subtotal; never exec untrusted code."""
    if not isinstance(source, str) or len(source) > 180:
        return False
    try:
        tree = ast.parse(source)
        f = tree.body[0]
        r = f.body[0]
        b = r.value
        return (len(tree.body) == 1 and isinstance(f, ast.FunctionDef)
                and f.name == 'total' and len(f.args.args) == 1
                and f.args.args[0].arg == 'subtotal' and not f.args.defaults
                and not f.args.vararg and not f.args.kwarg and not f.args.kwonlyargs
                and not f.args.posonlyargs and not f.decorator_list
                and f.returns is None and f.args.args[0].annotation is None
                and len(f.body) == 1 and isinstance(r, ast.Return)
                and isinstance(b, ast.BinOp) and isinstance(b.op, ast.Mult)
                and isinstance(b.left, ast.Name) and b.left.id == 'subtotal'
                and isinstance(b.right, ast.Constant) and type(b.right.value) in (int, float)
                and 0 <= b.right.value <= 1.5)
    except (SyntaxError, IndexError, AttributeError, TypeError):
        return False


def decision(action):
    if not isinstance(action, dict):
        return 'invalid_action'
    tool = action.get('tool')
    if not isinstance(tool, str):
        return 'invalid_tool'
    keys = {'inspect': {'tool', 'path'}, 'propose_patch': {'tool', 'path', 'before', 'after'},
            'apply_patch': {'tool', 'path', 'before', 'after'},
            'run_tests': {'tool', 'path'}}
    if tool not in keys:
        return 'tool_not_allowed'
    if set(action) != keys[tool]:
        return 'unexpected_arguments'
    if action.get('path') != PATH:
        return 'path_not_allowed'
    if tool in ('propose_patch', 'apply_patch'):
        if action.get('before') != BASE:
            return 'base_revision_mismatch'
        if not valid_source(action.get('after')):
            return 'source_policy_rejected'
    return None


@register_validator(name='sdlc-tool-permission', data_type='string')
class ToolPermission(Validator):
    def validate(self, value, metadata):
        try:
            action = json.loads(value)
            reason = decision(action)
        except (ValueError, TypeError):
            reason = 'invalid_action'
        return FailResult(error_message=reason) if reason else PassResult()


class ToolGuard:
    def __init__(self):
        self.guard = Guard().use(ToolPermission(on_fail='exception'))
        self.guard.configure(allow_metrics_collection=False)
        self.version = version('guardrails-ai')

    def check(self, action):
        try:
            result = self.guard.validate(json.dumps(action, allow_nan=False))
            if not result.validation_passed:
                raise Rejected(decision(action) or 'framework_rejected')
        except Rejected:
            raise
        except Exception:
            raise Rejected(decision(action) or 'guard_unavailable') from None
        return action
