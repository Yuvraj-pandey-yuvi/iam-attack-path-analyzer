# iampath: AWS IAM attack-path analyzer

[![CI](https://github.com/Yuvraj-pandey-yuvi/iam-attack-path-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Yuvraj-pandey-yuvi/iam-attack-path-analyzer/actions/workflows/ci.yml)

> **Status: work in progress.** v1 is being built in phases. This README describes the planned v1 scope.

iampath finds privilege-escalation paths in an AWS account. It collects IAM data
into a snapshot, evaluates the policies offline, builds a graph of which principal
can become which, and reports every path from a non-admin principal to admin. It
also suggests chokepoints: the fewest permission removals that break those paths.

## How it works

```
collect -> snapshot.json -> evaluate policies -> 21 rules -> graph
        -> admin marking + BFS -> findings.json -> CLI summary / graph.html
```

The collector is read-only and runs under a custom least-privilege policy
(`policies/collector-policy.json`). Everything after collection runs offline.

## Scope (v1)

21 escalation techniques, starting from Rhino Security Labs' classic IAM paths:

- **Grant (9):** a principal can give itself or another principal more permissions:
  CreatePolicyVersion, SetDefaultPolicyVersion, AttachUserPolicy, AttachGroupPolicy,
  AttachRolePolicy, PutUserPolicy, PutGroupPolicy, PutRolePolicy, AddUserToGroup.
- **Reach (12):** a principal can act as another principal: CreateAccessKey,
  CreateLoginProfile, UpdateLoginProfile, UpdateAssumeRolePolicy, sts:AssumeRole,
  lambda:UpdateFunctionCode, ssm:SendCommand, and iam:PassRole combined with
  EC2, Lambda (two variants), CloudFormation or ECS.

## Known limitations

- Service control policies (SCPs) and permission boundaries are ignored, so
  accounts in AWS Organizations may show false positives.
- Resource-based policies other than role trust policies are not evaluated.
- Policy conditions are flagged, not evaluated.
- Single account only: cross-account paths are out of scope.
- Not covered: Data Pipeline (closed to new customers) and the Glue
  dev-endpoint paths (legacy and costly to test).

## Development

Requires Python 3.14.

```bash
git clone https://github.com/Yuvraj-pandey-yuvi/iam-attack-path-analyzer.git
cd iam-attack-path-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -e . --group dev
python -m ruff check . && python -m pytest
```

## Safety

Snapshots contain real account data. They are git-ignored by default
(`/snapshot*.json`, `/out/`). Never commit them.
