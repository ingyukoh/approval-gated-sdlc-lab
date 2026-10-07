"""Decode one bounded JSON proposal. Never execute surrounding model text."""
import json,re

def parse_proposal(raw):
    if not isinstance(raw,str) or len(raw)>6000:raise ValueError('model_output_too_large')
    try:return json.loads(raw),'strict_json'
    except ValueError:pass
    blocks=re.findall(r'```(?:json)?\s*\n(.*?)\n\s*```',raw,re.DOTALL)
    if len(blocks)!=1:raise ValueError('expected_one_json_block')
    proposal=json.loads(blocks[0])
    if not isinstance(proposal,dict):raise ValueError('expected_object')
    return proposal,'single_fenced_json_block'
