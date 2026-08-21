# Deploying a Freewire server

For a personal server on any Linux host with a public IP. The Marketplace
AMI path in `cloudformation-spec.md` is a different, heavier thing; this is
what you want to run one for yourself.

## Why this is short

You do not need a domain or a certificate. The client pins the server's
WireGuard public key, and that pin — not the certificate — is what
establishes trust, so a self-signed certificate on a bare IP is fine. See
`error-states-spec.md` under TRUST.

## Steps

Build the binary for the target architecture:

```bash
# Graviton / arm64 (t4g.*)
cd server && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../deploy/freewire-server ./cmd/freewire-server

# Intel / amd64 (t3.*)
cd server && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../deploy/freewire-server ./cmd/freewire-server
```

Copy and run:

```bash
scp -r deploy ubuntu@<server-ip>:~/
ssh ubuntu@<server-ip> "cd deploy && sudo ./provision.sh"
```

The script prints the server's public key. Pin it on the Mac:

```bash
defaults write com.freewire.vpn.Freewire pinnedServerKey '<key from the script>'
```

Then point the client at the server address in `AppDelegate.swift`.

## Ports

| Port | Protocol | Purpose |
|---|---|---|
| 443 | tcp | TLS transport and the API |
| 51820 | udp | WireGuard |
| 53 | udp | DNS tunnel |
| 4500 | udp | ICMP/UDP tunnel |

Open these in the instance's security group. 443 and 51820 are the ones that
matter for a working tunnel; 53 and 4500 only exercise the fallback paths.

## Sizing

`t4g.small` (~$12/mo) or Lightsail ($5/mo, 2 TB bundled) is more than enough
for one user. Bandwidth, not compute, is what costs money at scale: EC2 meters
egress at $0.09/GB beyond 100 GB/month, which is fine for personal use and
ruinous for a free service. See the note in `deploy/COSTS.md` before putting
anyone else on it.

## What the script does

- Installs the binary and a systemd unit that restarts on failure
- Enables IPv4 forwarding
- Adds the MASQUERADE rule, and persists it

That NAT rule is the step most self-hosted VPN guides omit. Without it the
tunnel comes up, the handshake completes, and no traffic passes: forwarded
packets keep their `10.0.0.0/24` source and nothing upstream can route the
replies back.

## AWS credentials

Do not use a root access key. Create an IAM user:

IAM → Users → Create user → attach policies → Security credentials →
Create access key → Command Line Interface. Then `aws configure`.

`AmazonEC2FullAccess` plus `AmazonSSMReadOnlyAccess` will work and is the
quickest way to get moving. `iam-policy.json` here is the scoped equivalent —
the same capability without blanket EC2 rights — and can be attached as a
customer-managed policy instead.

The SSM permission is only there because the launch script asks AWS for the
current Ubuntu AMI ID rather than pinning a stale one.
