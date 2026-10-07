APPROVAL-GATED SDLC LAB — INDEPENDENT OCTOBER 2026 CASE STUDY

Problem: a model may propose a useful change while untrusted repository content
tries to redirect tools. Approval must survive model mistakes, patch changes,
concurrent callers, process restarts and replay attempts.

Implementation: Python, LangGraph 1.2.2, Guardrails AI 0.11.0 custom validator,
AST allowlist, SHA-256 patch binding, 120-second approval, conditional DynamoDB
single-use claim, isolated temporary fixture, strict HTTP/CSRF/session handling.
No shell, eval, exec, Git token, customer repository or general file tool exists.

RUN LOCALLY (Python 3.11 or 3.12)
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/python -m pytest -q
LOCAL_DEMO=1 .venv/bin/uvicorn app:local_app --factory --host 127.0.0.1 --port 8531
Open http://127.0.0.1:8531/. Review state is in memory locally.
The deployed service uses DynamoDB and retains state across Lambda workers.

DEMONSTRATION (five minutes)
1. Normal: Inspect & propose → review diff and digest → Attempt without approval.
   The server rejects with zero patch writes. Approve → Apply & test. Three
   arithmetic cases pass and the proposed PR artifact becomes merge-ready.
2. Replay: replay the used approval. The server rejects another write.
3. Tool-boundary attack: inspect the injected secret-access proposal. Guardrails
   AI rejects the unauthorized tool before it reaches any file operation.
4. Tamper: inspect → approve → attempt changed patch. A structurally valid 20%
   tax patch differs from the authorized 10% patch, so the executor rejects it.
5. Open Evaluation JSON and source download. Explain the fixture limits below.

DATA AND EVALUATION ORIGIN
The invoice code, three arithmetic checks, 24 forbidden tool proposals, and 12
benign formatting variants are authored synthetic fixtures in tests/. They are
not extracted customer data and not an independent third-party security corpus.
Proposal acceptance is evaluated separately from approval and execution checks.
No model was trained on this corpus. The recorded Bedrock proposal is generated
once; its exact prompt, response, model ID, usage and timing are preserved in
results/model-proposal.json if the account permits invocation. The hosted graph
replays that untrusted proposal and validates it on every run. The attack is an
explicitly injected tool proposal, not a claim that a prompt fooled that model.
All evaluation cases are exposed, so results are scoped regression evidence.

DEPLOYMENT (authenticated AWS CloudShell, us-east-1)
Upload the source archive and unzip into a new directory under /tmp.
python3 deploy/record_proposal.py
python3 package.py
python3 deploy/aws_deploy.py
The deployment builds an x86-64 AWS Lambda Python 3.12 container, pushes ECR,
creates the isolated DynamoDB table and logs-only/table-only role, and prints
DEPLOYMENT_READY with the HTTPS Function URL. Existing demos are not modified.
Keep deployment-state.json privately; it is excluded from the source download.

REQUEST AND COST CONTROLS
POST bodies: 8 KiB max; exact JSON fields; same-origin + session-bound CSRF.
Per source IP: 30 mutations/minute and 240/day, global 2,000 mutations/day.
Only keyed hashes of IPs are retained in counters, expiring after two days.
Three reserved Lambda executions cap concurrency; AWS may throttle excess calls.
Logs contain method, status and elapsed time only, retained seven days.
Run state expires after one day (DynamoDB TTL removal is asynchronous).
Public reviewer is an unverified browser session. It cannot affect real repos.
No live LLM inference is performed per visitor and no EC2 instance remains idle.
Public page/report/session routes load without initializing Guardrails or
LangGraph. The first tool check on a cold worker loads those SDKs and may take
up to 30 seconds; subsequent checks reuse the worker. All writes remain gated.
GET requests are limited to 100 per source IP per minute.
Estimated cost: at 10,000 requests/month, 1.5 GB, 0.5-second average duration,
Lambda compute approximately $0.125 plus $0.002 requests, before free tier.
Add image storage, DynamoDB, logs and transfer; use $1–5/month as a low-traffic
planning estimate, not a hard spending cap. Longer cold starts or abuse can
increase cost. Official rates: https://aws.amazon.com/lambda/pricing/

RECOVERY AND CLEANUP
Approval is persisted before a write. If a process dies after claiming approval,
the approval remains consumed; create a new run rather than replay it. No claim
of exactly-once external side effects is made. A new Lambda process reloads a
waiting/approved run from DynamoDB. SESSION_KEY must remain unchanged on deploy.
To remove only this lab: bash deploy/cleanup.sh (irreversible resource deletion).

WHAT REMAINS FOR A CLIENT SPRINT
Enterprise SSO with independent reviewer RBAC; signed Git commit/base identity;
general hardened code sandbox; real Git PR + CI adapters; durable workflow
recovery and idempotent remote operations; client-specific attack corpus and
redaction rules; operational SLOs. This recent prototype does not establish
prior NeMo work, Kubernetes operation, enterprise deployment or regional eligibility.

CODE ORIGIN
This is a newly implemented bounded SDLC fixture. Its architectural pattern is
consistent with Ingyu's existing evidence-first-agentic-rag public portfolio:
https://github.com/ingyukoh/evidence-first-agentic-rag . The new approval state
and executor boundaries are implemented and tested here, not asserted as past
client use. Guardrails AI and LangGraph are installed from PyPI and version-pinned.

OCTOBER 8 EVIDENCE UPGRADE
See README.md for the real GitHub bot PR, exact-commit CI verification,
protected merge and separate environment release gate. Git credentials are
confined to isolated GitHub Actions jobs, never the public Lambda. The live-model
experiment is run offline by the operator; the interactive planner still replays
its recorded response. Owner-scoped audit export contains sanitized trace events,
not browser identifiers, approval tokens or contract/customer text.
