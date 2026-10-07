"""Record one real Bedrock proposal; preserve response and usage for inspection.

Run in authenticated AWS CloudShell. The deployed endpoint replays this proposal;
it never receives model credentials or grants a model approval rights.
"""
import hashlib
import json
import re
from pathlib import Path
import sys
import time
import boto3
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
BASE = 'def total(subtotal):\n    return subtotal * 0.10\n'
PATH = 'src/invoice.py'

model = 'amazon.nova-micro-v1:0'
prompt = 'Fix this disposable invoice function. Requirement: subtotal plus 10% tax. Output only a JSON object with keys tool, path, before, after. tool is propose_patch. path is ' + PATH + '. before must match exactly ' + json.dumps(BASE) + '. after must be one def total(subtotal) returning subtotal * 1.10. Do not include a markdown fence.'
start = time.perf_counter()
result = boto3.client('bedrock-runtime', region_name='us-east-1').converse(
    modelId=model, messages=[{'role': 'user', 'content': [{'text': prompt}]}],
    inferenceConfig={'maxTokens': 400, 'temperature': 0})
raw = ''.join(x.get('text', '') for x in result['output']['message']['content'])
try:
    try:
        proposal = json.loads(raw)
        extraction = 'strict JSON'
    except ValueError:
        blocks = re.findall(r'```json\s*(.*?)\s*```', raw, re.DOTALL)
        if len(blocks) != 1:
            raise
        proposal = json.loads(blocks[0])
        extraction = 'single fenced JSON block; surrounding prose ignored and retained'
except ValueError:
    # Retain the raw response; fail rather than silently replace it with fixture output.
    Path('results/model-response-failed.txt').write_text(raw)
    raise
if set(proposal) != {'tool', 'path', 'before', 'after'} or proposal.get('tool') != 'propose_patch' or proposal.get('path') != PATH or proposal.get('before') != BASE:
    raise RuntimeError('Model proposal has unexpected fields or base revision')
data = {'proposal': proposal, 'provenance': {'mode': 'replay of recorded Bedrock model proposal',
        'model_id': model, 'recorded_utc_epoch': round(time.time(), 3),
        'temperature': 0, 'extraction': extraction, 'generation_ms': round((time.perf_counter() - start) * 1000, 2),
        'usage': result['usage'], 'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest()},
        'prompt': prompt, 'raw_response': raw}
Path('results/model-proposal.json').write_text(json.dumps(data, indent=2) + '\n')
print(json.dumps(data, indent=2))
