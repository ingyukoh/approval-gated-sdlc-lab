"""Validate a recorded/live proposal and change only the sandbox invoice file.

This creates a proposal branch, not approval to merge or deploy it.
Never evaluate model-generated shell commands or workflow files.
"""
import argparse
import hashlib
import json
from pathlib import Path
from engine import digest
from policy import BASE, PATH, ToolGuard, Rejected


def prepare(proposal, root):
    ToolGuard().check(proposal)
    if proposal['tool'] != 'propose_patch':
        raise Rejected('planner_may_only_propose_patch')
    path = root / PATH
    if path.is_symlink() or path.resolve().parent != (root / 'src').resolve():
        raise Rejected('path_not_allowed')
    if path.read_text() != BASE:
        raise Rejected('base_revision_mismatch')
    path.write_text(proposal['after'])
    return {'action': 'prepare_git_proposal', 'decision': 'allowed',
            'patch_digest': digest(proposal), 'path': PATH,
            'file_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'merge_authorized': False, 'deployment_authorized': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--proposal', default='results/model-proposal.json')
    parser.add_argument('--output', default='/tmp/sdlc-git-proposal.json')
    args = parser.parse_args()
    record = json.loads(Path(args.proposal).read_text())
    evidence = prepare(record['proposal'], Path.cwd())
    Path(args.output).write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence))
