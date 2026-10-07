#!/usr/bin/env bash
set -euo pipefail
DEMO_NAME=ingyu-agentic-sdlc-lab-20261008
DEMO_REGION=us-east-1
# Removes only this isolated lab. Run after preserving any needed evaluation trace.
aws lambda delete-function --function-name "$DEMO_NAME" --region "$DEMO_REGION"
aws dynamodb delete-table --table-name "$DEMO_NAME" --region "$DEMO_REGION"
aws ecr delete-repository --repository-name "$DEMO_NAME" --force --region "$DEMO_REGION"
aws logs delete-log-group --log-group-name "/aws/lambda/$DEMO_NAME" --region "$DEMO_REGION"
aws iam delete-role-policy --role-name "$DEMO_NAME-role" --policy-name isolated-demo-state-and-logs
aws iam delete-role --role-name "$DEMO_NAME-role"
