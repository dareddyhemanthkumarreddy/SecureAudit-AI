# SecureAudit-AI

Privacy-preserving cloud storage integrity auditing using subset-based
signatures, an AI risk-scoring agent, and garlic-bundled auditor requests.

## What this does

Files are partitioned into blocks, signed in subsets before upload, and
monitored by an AI agent that scores each sub-block's risk of tampering.
Only risky sub-blocks are sent for verification, and requests to the
Third-Party Auditor are bundled with decoys (garlic bundling) so the
auditor cannot tell which blocks are actually being checked.

## Status

Actively under development — see progress_log.md for daily updates
and CHANGELOG.md for shipped milestones.

## Setup

pip install -r requirements.txt
python main.py
