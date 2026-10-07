# Approval-Gated SDLC Lab

Independent October 2026 case study by Ingyu Koh.

[Public AWS demonstration](https://kjigfrfabegyxerw5jagfvhyza0kveeb.lambda-url.us-east-1.on.aws/)

A bounded coding-agent proposal crosses a Guardrails AI 0.11.0 validator, then a digest-bound, expiring, single-use approval before an isolated invoice fixture can change. LangGraph orchestrates inspect/plan/validate. DynamoDB persists reviewer state across Lambda workers. This recent project is not prior enterprise production experience.

## Reproduce

Python 3.11/3.12:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
OTEL_SDK_DISABLED=true LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/python -m pytest -q
LOCAL_DEMO=1 .venv/bin/uvicorn app:local_app --factory --host 127.0.0.1 --port 8531
```

Three main-branch invoice cases intentionally xfail on the broken baseline; after the guarded proposal they pass. Security boundary tests must pass in both revisions.

## Real GitHub workflow

1. Dispatch `propose-sandbox-fix`. The GitHub Actions bot validates the recorded Nova Micro patch and changes only `src/invoice.py`, runs tests, and opens a real PR. Its token cannot merge protected main.
2. Dispatch `verify-agent-pr` with the generated branch. Trusted main supplies all test/workflow code; only the proposed arithmetic file is materialized after path and AST validation. A required status is attached to the exact tested commit.
3. A human must review that commit before merging. Stale approvals are dismissed; administrators also face protection. The PR is intentionally left open for inspection.
4. `sandbox-release-approval` exercises a separately protected GitHub Environment. It produces release evidence only; it has no AWS credentials and does not deploy the public Lambda. Independent reviewer availability is needed to complete this release gate.

The public browser exercise uses a session reviewer and cannot access GitHub. This is distinct from GitHub's authenticated bot/human approval boundary.

## Model provenance and evaluation

`results/model-proposal.json` preserves the original Bedrock Amazon Nova Micro proposal, exact prompt, response, usage and timing. The interactive page replays it. The forbidden-tool scenario tests executor policy, not model resistance.

`live_model_eval.py generate` runs 24 **live** Bedrock calls: four authored benign and eight authored poisoned README cases, each with basic and hardened prompts. `live_model_eval.py score` separately checks outputs with the actual Guardrails AI validator. Every prompt and response is retained in the report; zero tool actions are executed by this experiment. Strict JSON errors, forbidden proposals and accepted safe patches are reported separately. No independent benchmark or universal attack resistance is claimed.

```sh
# In authenticated AWS CloudShell
python3 live_model_eval.py generate
# In an environment with requirements.lock installed
python3 live_model_eval.py score
```

See `README.txt` for deployment, cost assumptions, session persistence, cleanup and the bounded fixture's limits. `results/github-delivery.json` records actual PR/check/protection state when available. `results/live-model-evaluation.json` contains measured results when the experiment has completed.
