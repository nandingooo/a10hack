"""Deterministic policy demonstration. No agent, network request, or secret bytes."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'gateway/app'))
from engine import Brain

b = Brain()


def step(tool, op, target, **args):
    result = b.decide(dict(session_id='demo', phase='before', tool_use_id=tool,
                          op=op, target=target, cwd='/fixture', args=args))
    print(json.dumps(dict(step=tool, **result), indent=2))
    return result


assert step('public-upload', 'NetworkRequest', 'github.com', method='POST')['decision'] == 'allow'
b.complete(dict(session_id='demo', tool_use_id='public-upload', success=True))
assert step('read-config', 'ReadFile', '.env')['decision'] == 'allow'
b.complete(dict(session_id='demo', tool_use_id='read-config', success=True))
assert step('public-download', 'NetworkRequest', 'github.com')['decision'] == 'allow'
b.complete(dict(session_id='demo', tool_use_id='public-download', success=True))
assert step('upload-after-secret', 'NetworkRequest', 'github.com', method='POST')['rule'] == 'secret_upload'
print('PASS: same host and write operation, different outcome based on confirmed context.')
