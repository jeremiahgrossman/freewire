#!/usr/bin/env bash
# Launch a Freewire server on EC2 and provision it end to end.
#
#   ./launch-aws.sh [region]
#
# Creates: a key pair, a security group, and one t4g.small instance. Prints the
# public key to pin on the client. Tear it all down with ./destroy-aws.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${1:-us-east-1}"
NAME="freewire-server"
KEY_NAME="freewire-server"
KEY_FILE="$HOME/.ssh/freewire-server"
INSTANCE_TYPE="t4g.small"   # Graviton: cheaper per hour than t3 and plenty here

command -v aws >/dev/null || { echo "aws cli not installed" >&2; exit 1; }
aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1 || {
  echo "AWS credentials are not configured. Run: aws configure" >&2; exit 1; }
[[ -f "$KEY_FILE.pub" ]] || { echo "missing $KEY_FILE.pub" >&2; exit 1; }

echo "==> region: $REGION"

echo "==> key pair"
if ! aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" >/dev/null 2>&1; then
  aws ec2 import-key-pair --key-name "$KEY_NAME" \
    --public-key-material "fileb://$KEY_FILE.pub" --region "$REGION" >/dev/null
  echo "    imported"
else
  echo "    exists"
fi

echo "==> security group"
SG_ID="$(aws ec2 describe-security-groups --group-names "$NAME" --region "$REGION" \
          --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
  VPC_ID="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --region "$REGION" \
             --query 'Vpcs[0].VpcId' --output text)"
  SG_ID="$(aws ec2 create-security-group --group-name "$NAME" \
            --description "Freewire VPN server" --vpc-id "$VPC_ID" --region "$REGION" \
            --query 'GroupId' --output text)"

  # SSH is restricted to the address launching this; everything else has to be
  # open, because the whole point is reaching the server from hostile networks.
  MYIP="$(curl -s -m 5 https://api.ipify.org)/32"
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --ip-permissions \
      "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$MYIP,Description='ssh from deployer'}]" \
      "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0,Description='TLS transport'}]" \
      "IpProtocol=tcp,FromPort=8080,ToPort=8080,IpRanges=[{CidrIp=0.0.0.0/0,Description='API'}]" \
      "IpProtocol=udp,FromPort=51820,ToPort=51820,IpRanges=[{CidrIp=0.0.0.0/0,Description='WireGuard'}]" \
      "IpProtocol=udp,FromPort=53,ToPort=53,IpRanges=[{CidrIp=0.0.0.0/0,Description='DNS tunnel'}]" \
      "IpProtocol=udp,FromPort=4500,ToPort=4500,IpRanges=[{CidrIp=0.0.0.0/0,Description='ICMP/UDP tunnel'}]" \
    >/dev/null
  echo "    created $SG_ID (ssh limited to $MYIP)"
else
  echo "    exists $SG_ID"
fi

echo "==> latest Ubuntu 24.04 arm64 AMI"
AMI="$(aws ssm get-parameters --region "$REGION" \
        --names /aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id \
        --query 'Parameters[0].Value' --output text)"
echo "    $AMI"

RUNNING="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=$NAME" "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || true)"

if [[ -n "$RUNNING" && "$RUNNING" != "None" ]]; then
  echo "==> reusing running instance $RUNNING"
  INSTANCE_ID="$RUNNING"
else
  echo "==> launching $INSTANCE_TYPE"
  INSTANCE_ID="$(aws ec2 run-instances --region "$REGION" \
    --image-id "$AMI" --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" --security-group-ids "$SG_ID" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
    --query 'Instances[0].InstanceId' --output text)"
  echo "    $INSTANCE_ID"
  aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"
fi

IP="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
      --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
echo "==> public IP: $IP"

echo "==> waiting for ssh"
for _ in $(seq 1 60); do
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -i "$KEY_FILE" \
      "ubuntu@$IP" true 2>/dev/null && break
  sleep 5
done

echo "==> provisioning"
cp "$HERE/freewire-server-arm64" "$HERE/freewire-server"
scp -q -o StrictHostKeyChecking=accept-new -i "$KEY_FILE" \
    "$HERE/provision.sh" "$HERE/freewire-server" "ubuntu@$IP:~/"
rm -f "$HERE/freewire-server"
ssh -o StrictHostKeyChecking=accept-new -i "$KEY_FILE" "ubuntu@$IP" \
    "chmod +x provision.sh && sudo ./provision.sh"

cat <<EOF

  Done. Instance $INSTANCE_ID at $IP

  Point the client at it:
    macos/Freewire/Freewire/AppDelegate.swift -> ServerAPI(host: "$IP")

  Pin the key printed above:
    defaults write com.freewire.vpn.Freewire pinnedServerKey '<key>'

  Tear down when finished (this instance bills by the hour):
    ./destroy-aws.sh $REGION
EOF
