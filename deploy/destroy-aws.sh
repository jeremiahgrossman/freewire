#!/usr/bin/env bash
# Remove everything launch-aws.sh created.
set -euo pipefail
REGION="${1:-us-east-1}"
NAME="freewire-server"

IDS="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=$NAME" "Name=instance-state-name,Values=running,pending,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text)"

if [[ -n "$IDS" ]]; then
  echo "terminating: $IDS"
  aws ec2 terminate-instances --instance-ids $IDS --region "$REGION" >/dev/null
  aws ec2 wait instance-terminated --instance-ids $IDS --region "$REGION"
  echo "terminated"
else
  echo "no instances found"
fi

# Release the Elastic IP. An allocated address that is not attached to a
# running instance bills by the hour, so leaving it behind turns a torn-down
# deployment into a standing charge.
ALLOC="$(aws ec2 describe-addresses --region "$REGION" \
  --filters "Name=tag:Name,Values=$NAME" --query 'Addresses[0].AllocationId' \
  --output text 2>/dev/null || true)"
if [[ -n "$ALLOC" && "$ALLOC" != "None" ]]; then
  aws ec2 release-address --allocation-id "$ALLOC" --region "$REGION" 2>/dev/null \
    && echo "elastic ip released" || echo "elastic ip could not be released"
fi

# The security group cannot be deleted until its instances are gone, which the
# wait above guarantees.
aws ec2 delete-security-group --group-name "$NAME" --region "$REGION" 2>/dev/null \
  && echo "security group deleted" || echo "security group not found or still in use"
echo "key pair left in place; delete with: aws ec2 delete-key-pair --key-name $NAME --region $REGION"
