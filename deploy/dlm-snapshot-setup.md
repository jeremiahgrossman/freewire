# EBS snapshot policy — setup steps (needs IAM-admin access)

The `freewire-deploy` IAM user cannot grant itself these permissions (it can't
even read its own attached policies). Whoever has root/IAM-admin access on
account `216989115408` needs to run this once.

## 1. Add this statement to `freewire-deploy`'s policy (or attach as a separate policy)

**Already done (2026-08-31):** `deploy/iam-policy.json` already carries the
`EBSSnapshotBackup`, `DLMServiceLinkedRole`, and `PassDLMRole` statements below
verbatim — this step is complete in the tracked policy file. What's still
missing is applying it: whoever has IAM-admin access needs to actually attach
the updated policy to the `freewire-deploy` user (or confirm it's already
attached) before moving on to steps 2–5, which remain genuinely pending.

For reference, the statements already in `deploy/iam-policy.json`:

```json
{
  "Sid": "EBSSnapshotBackup",
  "Effect": "Allow",
  "Action": [
    "ec2:CreateSnapshot",
    "ec2:DeleteSnapshot",
    "ec2:DescribeSnapshots",
    "ec2:DescribeVolumes",
    "dlm:CreateLifecyclePolicy",
    "dlm:GetLifecyclePolicy",
    "dlm:GetLifecyclePolicies",
    "dlm:UpdateLifecyclePolicy",
    "dlm:TagResource"
  ],
  "Resource": "*"
},
{
  "Sid": "DLMServiceLinkedRole",
  "Effect": "Allow",
  "Action": "iam:CreateServiceLinkedRole",
  "Resource": "arn:aws:iam::*:role/aws-service-role/dlm.amazonaws.com/AWSServiceRoleForDataLifecycleManager",
  "Condition": {
    "StringEquals": { "iam:AWSServiceName": "dlm.amazonaws.com" }
  }
},
{
  "Sid": "PassDLMRole",
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::216989115408:role/aws-service-role/dlm.amazonaws.com/AWSServiceRoleForDataLifecycleManager"
}
```

Apply via the console (IAM → Users → freewire-deploy → Add permissions), or:
```bash
aws iam put-user-policy --user-name freewire-deploy \
  --policy-name freewire-deploy-snapshots \
  --policy-document file://deploy/dlm-iam-addition.json \
  --profile <your-admin-profile>
```

## 2. Tag the volume

```bash
aws ec2 create-tags --resources vol-0ff5771bd74fb93a8 --region us-east-1 \
  --tags Key=Backup,Value=freewire-server
```

## 3. Create the DLM service-linked role (one-time, account-wide)

```bash
aws iam create-service-linked-role --aws-service-name dlm.amazonaws.com --region us-east-1
```
(Safe to re-run — errors harmlessly if it already exists.)

## 4. Create the lifecycle policy

```bash
aws dlm create-lifecycle-policy --region us-east-1 \
  --execution-role-arn "arn:aws:iam::216989115408:role/aws-service-role/dlm.amazonaws.com/AWSServiceRoleForDataLifecycleManager" \
  --description "freewire-server EBS daily snapshots" \
  --state ENABLED \
  --policy-details '{
    "ResourceTypes": ["VOLUME"],
    "TargetTags": [{"Key": "Backup", "Value": "freewire-server"}],
    "Schedules": [{
      "Name": "DailySnapshot",
      "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
      "RetainRule": {"Count": 7},
      "CopyTags": true
    }]
  }'
```

This snapshots `/var/lib/freewire/` (the WireGuard key, `peers.json`, the
spent-token journal, the ACME cert) daily at 03:00 UTC, keeping 7 days —
recovers full server identity, no client re-pin needed, for the instance/
volume-loss case. Does NOT cover an AWS-account-level loss (see CLAUDE.md's
redundancy audit notes for that separate, lower-priority follow-up).

## 5. Verify

```bash
aws dlm get-lifecycle-policies --region us-east-1
```
Should show the new policy `ENABLED`. First snapshot fires at the next
scheduled time, not immediately.
