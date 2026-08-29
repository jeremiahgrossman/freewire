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
  # A third party's HTTP response decides who may SSH to this box, so it is
  # checked rather than trusted. An empty reply (the service is down, the
  # network is captive) would otherwise expand to "/32" and, depending on how
  # the AWS CLI parsed it, either fail confusingly or widen the rule. Anything
  # that is not a dotted quad stops the script.
  MYIP_RAW="$(curl -sf -m 5 https://api.ipify.org || true)"
  if [[ ! "$MYIP_RAW" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "could not determine this machine's public address (got '${MYIP_RAW}')." >&2
    echo "Set MYIP_OVERRIDE=x.x.x.x and re-run to choose it yourself." >&2
    [[ -n "${MYIP_OVERRIDE:-}" ]] || exit 1
    MYIP_RAW="$MYIP_OVERRIDE"
  fi
  for octet in ${MYIP_RAW//./ }; do
    if (( octet > 255 )); then
      echo "'$MYIP_RAW' is not a valid IPv4 address" >&2; exit 1
    fi
  done
  MYIP="$MYIP_RAW/32"
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --ip-permissions \
      "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$MYIP,Description='ssh from deployer'}]" \
    >/dev/null
  echo "    created $SG_ID (ssh limited to $MYIP)"
else
  echo "    exists $SG_ID"
fi

# Transport ports are opened on EVERY run, not only when the group is created.
#
# They used to be part of the create branch, so a group that already existed
# never gained a rule added later -- a new listener would deploy, bind, and be
# silently unreachable from the internet. That is worse than an outright failure:
# the client reports the carrier as blocked, which is indistinguishable from a
# captive portal blocking it, and the wrong conclusion gets drawn from a field
# test. Each rule is added independently and an already-exists error is ignored,
# which is what makes this idempotent.
open_port() { # proto port description
  local out
  if out="$(aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
      --ip-permissions \
        "IpProtocol=$1,FromPort=$2,ToPort=$2,IpRanges=[{CidrIp=0.0.0.0/0,Description='$3'}]" \
      2>&1)"; then
    echo "    opened $1/$2 ($3)"
  elif grep -q "InvalidPermission.Duplicate" <<<"$out"; then
    : # already open; nothing to do
  else
    echo "    WARNING: could not open $1/$2: $(tr '\n' ' ' <<<"$out")" >&2
  fi
}
open_port tcp 443   'TLS transport'
open_port tcp 8080  'API'
open_port udp 51820 'WireGuard'
open_port udp 53    'DNS tunnel'
open_port udp 4500  'ICMP/UDP tunnel'
# Reachability probe responder (server/internal/transport/probe.go). Without
# these the probe battery reports UDP/443 and UDP/123 as blocked everywhere,
# which reads as "the portal blocks them" and would sink the carrier decision on
# a false negative. The responder answers only magic-gated, non-amplifying
# probes, so an open port here is not an NTP or QUIC service.
open_port udp 443   'probe responder (would-be QUIC carrier)'
open_port udp 123   'probe responder (would-be NTP carrier)'
# ACME HTTP-01 challenge (needed for a publicly trusted origin certificate,
# which CloudFront requires). Port 80 also answers the TCP/80 reachability probe
# -- as autocert's fallback handler when ACME is on, and as a standalone
# responder when it is off -- so the rule is live either way now.
open_port tcp 80    'ACME HTTP-01 challenge (also answers the TCP/80 probe)'
# TCP probe responder. The DNS carrier is UDP-only on both ends, so whether a
# portal that allow-lists UDP/53 also passes TCP/53 has never been measured --
# and DNS-over-TCP moves far more payload per query, which is what throttles us.
# Same rule as the UDP probe ports: without the ingress rule the battery reports
# these blocked everywhere and the carrier decision turns on a false negative.
open_port tcp 53    'probe responder (would-be DNS-over-TCP carrier)'
open_port tcp 853   'probe responder (would-be DoT-class carrier)'

# IPv6 ingress, mirroring the v4 ports, so a client on a v6-capable network can
# reach WireGuard (and the other carriers) over IPv6. Same idempotent shape as
# open_port but with an Ipv6Ranges rule.
open_port6() { # proto port description
  local out
  if out="$(aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
      --ip-permissions \
        "IpProtocol=$1,FromPort=$2,ToPort=$2,Ipv6Ranges=[{CidrIpv6=::/0,Description='$3 v6'}]" \
      2>&1)"; then
    echo "    opened $1/$2 v6 ($3)"
  elif grep -q "InvalidPermission.Duplicate" <<<"$out"; then
    :
  else
    echo "    WARNING: could not open $1/$2 v6: $(tr '\n' ' ' <<<"$out")" >&2
  fi
}
open_port6 udp 51820 'WireGuard'
open_port6 tcp 443   'TLS/WSS'
open_port6 udp 443   'UDP443'
open_port6 tcp 8080  'API'
open_port6 udp 53    'DNS tunnel'
open_port6 udp 4500  'ICMP/UDP tunnel'
open_port6 tcp 53    'probe responder (DNS-over-TCP)'
open_port6 tcp 853   'probe responder (DoT-class)'

# IPv6 addressing for the VPC/subnet/route/instance, so the server has a global
# v6 address and the config API can advertise it (endpoint_host_v6). All steps
# are additive (v6 only) and idempotent -- they never touch the v4 path. Ubuntu
# brings the address up on its own via RA, and wireguard-go binds dual-stack, so
# no OS or server change is needed beyond this.
echo "==> IPv6 addressing"
VPC_ID="$(aws ec2 describe-security-groups --group-ids "$SG_ID" --region "$REGION" \
           --query 'SecurityGroups[0].VpcId' --output text)"
V6_VPC="$(aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --region "$REGION" \
           --query 'Vpcs[0].Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock' --output text 2>/dev/null || true)"
if [[ -z "$V6_VPC" || "$V6_VPC" == "None" ]]; then
  aws ec2 associate-vpc-cidr-block --vpc-id "$VPC_ID" --amazon-provided-ipv6-cidr-block --region "$REGION" >/dev/null
  sleep 5
  V6_VPC="$(aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --region "$REGION" \
             --query 'Vpcs[0].Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock' --output text)"
  echo "    associated VPC v6 CIDR $V6_VPC"
else
  echo "    VPC v6 CIDR $V6_VPC"
fi
# The subnet gets the first /64 of the VPC /56.
SUBNET_ID="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=$NAME" "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[0].Instances[0].SubnetId' --output text 2>/dev/null || true)"
if [[ -n "$SUBNET_ID" && "$SUBNET_ID" != "None" ]]; then
  V6_SUBNET="$(aws ec2 describe-subnets --subnet-ids "$SUBNET_ID" --region "$REGION" \
               --query 'Subnets[0].Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock' --output text 2>/dev/null || true)"
  if [[ -z "$V6_SUBNET" || "$V6_SUBNET" == "None" ]]; then
    SUB64="${V6_VPC%::/56}::/64"
    aws ec2 associate-subnet-cidr-block --subnet-id "$SUBNET_ID" --ipv6-cidr-block "$SUB64" --region "$REGION" >/dev/null 2>&1 \
      && echo "    associated subnet v6 CIDR $SUB64" || echo "    subnet v6 CIDR present"
  fi
  # ::/0 route to the IGW (additive; leaves v4 routes untouched).
  IGW_ID="$(aws ec2 describe-internet-gateways --region "$REGION" \
             --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
             --query 'InternetGateways[0].InternetGatewayId' --output text)"
  RT_ID="$(aws ec2 describe-route-tables --region "$REGION" \
            --filters "Name=association.subnet-id,Values=$SUBNET_ID" \
            --query 'RouteTables[0].RouteTableId' --output text)"
  [[ "$RT_ID" == "None" ]] && RT_ID="$(aws ec2 describe-route-tables --region "$REGION" \
            --filters "Name=vpc-id,Values=$VPC_ID" "Name=association.main,Values=true" \
            --query 'RouteTables[0].RouteTableId' --output text)"
  aws ec2 create-route --route-table-id "$RT_ID" --destination-ipv6-cidr-block ::/0 \
    --gateway-id "$IGW_ID" --region "$REGION" >/dev/null 2>&1 \
    && echo "    added ::/0 route via $IGW_ID" || echo "    ::/0 route present"
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

# A static address, because the client pins the server by IP: a public IP that
# changes on stop/start would break every connection with a trust error that
# looks alarming and is not.
ALLOC="$(aws ec2 describe-addresses --region "$REGION" \
  --filters "Name=tag:Name,Values=$NAME" --query 'Addresses[0].AllocationId' \
  --output text 2>/dev/null || true)"
if [[ -z "$ALLOC" || "$ALLOC" == "None" ]]; then
  ALLOC="$(aws ec2 allocate-address --domain vpc --region "$REGION" \
    --query 'AllocationId' --output text)"
  aws ec2 create-tags --resources "$ALLOC" --tags "Key=Name,Value=$NAME" --region "$REGION" 2>/dev/null || true
  echo "==> allocated elastic ip"
fi
aws ec2 associate-address --instance-id "$INSTANCE_ID" --allocation-id "$ALLOC" \
  --region "$REGION" >/dev/null 2>&1 || true
sleep 3

IP="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
      --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
echo "==> public IP: $IP"

# Give the instance a global IPv6 address (idempotent: skip if it already has
# one). Ubuntu configures it via RA on its own; the server auto-detects it and
# advertises it as endpoint_host_v6.
V6="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
      --query 'Reservations[0].Instances[0].Ipv6Address' --output text 2>/dev/null || true)"
if [[ -z "$V6" || "$V6" == "None" ]]; then
  ENI="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
         --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' --output text)"
  aws ec2 assign-ipv6-addresses --network-interface-id "$ENI" --ipv6-address-count 1 --region "$REGION" >/dev/null 2>&1 || true
  sleep 3
  V6="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
        --query 'Reservations[0].Instances[0].Ipv6Address' --output text 2>/dev/null || true)"
fi
[[ -n "$V6" && "$V6" != "None" ]] && echo "==> public IPv6: $V6"

echo "==> waiting for ssh"
for _ in $(seq 1 60); do
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -i "$KEY_FILE" \
      "ubuntu@$IP" true 2>/dev/null && break
  sleep 5
done

echo "==> provisioning"
cp "$HERE/freewire-server-arm64" "$HERE/freewire-server"
scp -q -o StrictHostKeyChecking=accept-new -i "$KEY_FILE" \
    "$HERE/provision.sh" "$HERE/freewire-nat.sh" "$HERE/freewire-server" "ubuntu@$IP:~/"
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
