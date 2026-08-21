# Freewire VPN — CloudFormation and AMI Specification

**Audience:** Server engineers and DevOps  
**Version:** 1.0  
**Last updated:** 2026-06-17

---

## Overview

Self-hosted Freewire servers are deployed via AWS Marketplace. A user clicks "Launch" and CloudFormation creates everything automatically. The user receives a QR code and config file to connect their devices. No manual server configuration is required.

This document specifies what the CloudFormation template creates, how the AMI is built, and what the deployment outputs.

---

## AWS Marketplace Listing

**Listing type:** AMI-based product with CloudFormation template  
**Supported instance types:** t3.small (minimum), t3.medium (recommended)  
**Supported regions at launch:** us-east-1, us-west-2, eu-west-1, ap-southeast-1  

The AMI contains the Freewire server binary pre-installed. The CloudFormation template wires up the networking, security group, and IAM role, then starts the binary on boot.

---

## CloudFormation Template Parameters

The user is prompted for these values when launching the stack. All have sensible defaults.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `InstanceType` | String | `t3.small` | EC2 instance type. t3.small supports ~50 concurrent peers. t3.medium ~200 peers. |
| `KeyPairName` | AWS::EC2::KeyPair::KeyName | (none) | Optional. SSH key pair for emergency access. Leave blank for no SSH access (recommended). |
| `VpcId` | AWS::EC2::VPC::Id | (default VPC) | VPC to deploy into. Default VPC is fine for most users. |
| `SubnetId` | AWS::EC2::Subnet::Id | (first public subnet) | Subnet for the server. Must be a public subnet with an internet gateway. |
| `SetupPassword` | String (NoEcho) | (auto-generated) | Password for the server web dashboard. Auto-generated if left blank. |

---

## Resources Created

### EC2 Instance

```yaml
FreewireServer:
  Type: AWS::EC2::Instance
  Properties:
    ImageId: !FindInMap [AMIMap, !Ref "AWS::Region", AMI]
    InstanceType: !Ref InstanceType
    SubnetId: !Ref SubnetId
    SecurityGroupIds:
      - !Ref FreewireSecurityGroup
    IamInstanceProfile: !Ref FreewireInstanceProfile
    KeyName: !If [HasKeyPair, !Ref KeyPairName, !Ref "AWS::NoValue"]
    UserData:
      Fn::Base64: !Sub |
        #!/bin/bash
        # Write setup password to config
        echo "FREEWIRE_SETUP_PASSWORD=${SetupPassword}" >> /etc/freewire/env
        # Start and enable Freewire service
        systemctl enable freewire
        systemctl start freewire
    Tags:
      - Key: Name
        Value: !Sub "freewire-server-${AWS::StackName}"
```

**Root volume:** 8 GB gp3 EBS. Sufficient for the binary, logs, and generated WireGuard keypair.

**Auto-assigned public IP:** Yes. The server's public IP is the endpoint clients connect to.

**Elastic IP:** Not created by default (costs money when stopped). If the user wants a stable IP that survives instance stop/start, they can associate an EIP manually.

---

### Security Group

```yaml
FreewireSecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Freewire VPN server
    VpcId: !Ref VpcId
    SecurityGroupIngress:
      # WireGuard (open network path)
      - IpProtocol: udp
        FromPort: 51820
        ToPort: 51820
        CidrIp: 0.0.0.0/0
      # TLS/443 path
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 0.0.0.0/0
      # Server web dashboard (HTTPS)
      - IpProtocol: tcp
        FromPort: 8443
        ToPort: 8443
        CidrIp: 0.0.0.0/0
      # ICMP (for ICMP tunnel path)
      - IpProtocol: icmp
        FromPort: 8   # echo request
        ToPort: -1
        CidrIp: 0.0.0.0/0
    SecurityGroupEgress:
      # All outbound allowed (server needs to forward user traffic)
      - IpProtocol: -1
        CidrIp: 0.0.0.0/0
```

**Note on DNS tunnel:** The DNS tunnel path uses port 53 UDP, but traffic arrives at Freewire's authoritative DNS server for `tunnel.freewire.com` (not the self-hosted server). Self-hosted servers do not participate in the DNS tunnel path. If a user's network blocks TLS/443 and falls through to DNS tunnel, the DNS tunnel terminates at the managed server infrastructure. Self-hosted servers are reachable via WireGuard UDP and TLS/443 only.

**SSH (port 22):** Not opened. Users manage the server via the web dashboard. Emergency access via AWS Systems Manager Session Manager (no port required — see IAM role below).

---

### IAM Role and Instance Profile

```yaml
FreewireRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: ec2.amazonaws.com
          Action: sts:AssumeRole
    ManagedPolicyArns:
      # SSM Session Manager for emergency shell access (no SSH port required)
      - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
    Policies:
      - PolicyName: FreewireServerPolicy
        PolicyDocument:
          Statement:
            # Allow the server to fetch its own binary updates from S3
            - Effect: Allow
              Action:
                - s3:GetObject
              Resource:
                - arn:aws:s3:::freewire-server-releases/*
            # Allow CloudFormation signal on boot (for stack creation health check)
            - Effect: Allow
              Action:
                - cloudformation:SignalResource
              Resource: !Ref "AWS::StackId"
```

The IAM role is intentionally minimal. The server has no access to other AWS services, other users' resources, or Freewire's infrastructure.

---

### Elastic IP (Optional — not created by default)

Not included in the default template. Users who want a stable IP can add an EIP manually or use the AWS console. Documented in the server web dashboard's help text.

---

## AMI Contents

The AMI is a hardened Amazon Linux 2023 image with:

- **Freewire server binary** at `/usr/local/bin/freewire-server`
- **systemd service** at `/etc/systemd/system/freewire.service`
- **Config directory** at `/etc/freewire/` (empty at AMI build time; populated on first boot)
- **WireGuard kernel module** pre-installed (wireguard-go userspace as fallback)
- **Auto-update service** that checks `s3://freewire-server-releases/latest` on boot and updates if a newer version is available

### First boot sequence

On first boot, the `freewire-server` binary:
1. Generates a WireGuard keypair and writes the private key to `/etc/freewire/server.key` (mode 600)
2. Writes the public key to `/etc/freewire/server.pub`
3. Generates a self-signed TLS certificate for the web dashboard
4. Reads `FREEWIRE_SETUP_PASSWORD` from `/etc/freewire/env` (written by UserData)
5. Starts the WireGuard interface, TLS/443 listener, ICMP listener, and web dashboard
6. Signals CloudFormation that the stack is healthy via `cloudformation:SignalResource`

---

## CloudFormation Outputs

After the stack is created, the following outputs are available in the CloudFormation console. They are also displayed as the final step of the Marketplace launch flow.

| Output | Description | Example |
|---|---|---|
| `ServerEndpoint` | Public IP address of the server | `54.210.13.7` |
| `ServerPort` | WireGuard UDP port | `51820` |
| `DashboardURL` | URL of the server web dashboard | `https://54.210.13.7:8443` |
| `SetupPassword` | Dashboard setup password (masked after first login) | (masked) |
| `ServerPublicKey` | Server's WireGuard public key | `abc123...==` |

The Freewire client app uses `ServerEndpoint`, `ServerPort`, and `ServerPublicKey` to generate the client config (QR code / config file).

---

## Stack Lifecycle

### Update
CloudFormation updates are used only to change instance type or security group rules. The Freewire binary updates itself via the auto-update mechanism — no CloudFormation update is needed for software updates.

### Stop/Start
If the user stops the EC2 instance (to save cost), the public IP changes on restart (unless an Elastic IP is used). A new QR code / config file must be generated and re-imported on all connected devices.

### Delete
Deleting the CloudFormation stack terminates the EC2 instance, deletes the security group, and deletes the IAM role. The EBS root volume is deleted with the instance (no persistent user data is stored outside the instance).

**The WireGuard private key is stored on the instance root volume only.** Deleting the stack permanently destroys it. Connected devices will need to re-import a new config after a new stack is deployed. This is documented in the dashboard and in the SELFHOST-4 error state.

---

## Instance Sizing Guide

| Instance | vCPU | RAM | Concurrent peers | Monthly cost (on-demand) |
|---|---|---|---|---|
| t3.small | 2 | 2 GB | ~50 | ~$15 |
| t3.medium | 2 | 4 GB | ~200 | ~$30 |
| t3.large | 2 | 8 GB | ~500 | ~$60 |

Most personal/family use cases (1–5 devices) are comfortably served by t3.small. t3.medium is recommended for small teams.

Bandwidth is the more common constraint than CPU or RAM. AWS charges $0.09/GB outbound after the first 100 GB/month free. A user doing 50 GB/month of VPN traffic adds approximately $4.50/month in data transfer costs.
