# Freewire VPN — Certificate Management

**Audience:** Engineers and DevOps  
**Version:** 1.0  
**Last updated:** 2026-06-17

---

> **Superseded (2026-08-31):** the mechanism below (DNS-01 via `acme.sh`/Cloudflare, multi-server distribution through AWS Secrets Manager, `vpn.freewire.com`/`tunnel.freewire.com`) is not what shipped. There is one AWS server, and it provisions its own certificate automatically via `golang.org/x/crypto/acme/autocert` (HTTP-01, not DNS-01 — see `server/internal/certs/certs.go`), on the real domain `origin.pinghop.net` (`t.pinghop.net`'s DNS-tunnel zone is separate; see `CLAUDE.md`). No manual `certbot`/`acme.sh` step, no Secrets Manager, no multi-server distribution: `autocert.Manager` owns port 80 for the ACME HTTP-01 challenge (`m.HTTPHandler`) and renews on its own. A no-SNI/IP-direct client gets a self-signed fallback cert instead — that path exists specifically so IP-pinned clients aren't locked out by enabling ACME (see `CLAUDE.md`'s 2026-08-24 "certs.Build fix" note). The self-hosted dashboard and Developer ID rows below are real specs for deferred features, not currently active.

## Overview

Freewire uses TLS certificates in four places:

| Certificate | Used for | Type | Renewal |
|---|---|---|---|
| `vpn.freewire.com` | TLS/443 tunnel path on managed servers | Public CA (Let's Encrypt) | Automatic (90 days) |
| `tunnel.freewire.com` | DNS tunnel authoritative server HTTPS control plane | Public CA (Let's Encrypt) | Automatic (90 days) |
| Self-hosted server dashboard | Web dashboard HTTPS on self-hosted servers | Self-signed | On server deploy |
| macOS Developer ID | App bundle signing + notarization | Apple Developer ID | Annual |

---

## 1. `vpn.freewire.com` — Managed Server TLS Certificate

Used by the TLS/443 tunnel path. Every Freewire managed server presents this certificate when a client connects to port 443. The client validates the certificate against system trust roots — no certificate pinning.

**Why no certificate pinning:** Certificate pinning would require a client update every time the certificate is rotated. Since Let's Encrypt certificates expire every 90 days, pinning creates an operational risk (certificate rotated, old clients stop working). The threat model — protecting against an adversary who can MITM the TLS/443 path — is adequately addressed by standard CA validation combined with the inner WireGuard encryption layer. Even if the TLS layer were stripped by a MITM, the WireGuard handshake would fail without the server's private key.

### Provisioning

Let's Encrypt certificate via `certbot` or `acme.sh`, with DNS-01 challenge (no HTTP server required on port 80):

```bash
# On the managed server (or in the certificate management pipeline)
acme.sh --issue \
  --dns dns_cf \          # Cloudflare DNS API for DNS-01 challenge
  -d vpn.freewire.com

# Certificate files
# /etc/acme.sh/vpn.freewire.com/vpn.freewire.com.cer   (certificate)
# /etc/acme.sh/vpn.freewire.com/vpn.freewire.com.key   (private key)
# /etc/acme.sh/vpn.freewire.com/fullchain.cer           (certificate + chain)
```

### Deployment

For managed servers, the certificate is deployed via the server binary's config directory:
```
/etc/freewire/tls.crt   (fullchain.cer)
/etc/freewire/tls.key   (private key, mode 600)
```

The `freewire-server` binary reads these files at startup. On certificate rotation, send `SIGHUP` to reload without restarting:
```bash
systemctl kill -s HUP freewire-server
```

### Renewal

`acme.sh` installs a cron job for automatic renewal at 60 days. The post-renewal hook sends `SIGHUP` to the running server process:
```bash
acme.sh --install-cert -d vpn.freewire.com \
  --reloadcmd "systemctl kill -s HUP freewire-server"
```

**Monitoring:** Set up a certificate expiry monitor (e.g., Datadog, UptimeRobot) with a 30-day warning threshold. Automatic renewal should never reach this threshold; the monitor is a safety net.

### Multiple managed servers

Each managed server in a region should present the same certificate for `vpn.freewire.com`. Use a shared certificate with the private key distributed to each server at deploy time via AWS Secrets Manager:

```bash
# Store in Secrets Manager (one-time setup)
aws secretsmanager create-secret \
  --name freewire/tls/vpn-freewire-com \
  --secret-string file://fullchain_and_key.json

# On server startup, retrieve and write to disk
aws secretsmanager get-secret-value \
  --secret-id freewire/tls/vpn-freewire-com \
  --query SecretString \
  --output text | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
    open('/etc/freewire/tls.crt','w').write(d['cert']); \
    open('/etc/freewire/tls.key','w').write(d['key'])"
```

The IAM role for managed servers (distinct from the self-hosted CloudFormation role) must include `secretsmanager:GetSecretValue` for this secret ARN.

---

## 2. `tunnel.freewire.com` — DNS Tunnel Authoritative Server

The DNS tunnel authoritative servers have an HTTPS control plane for management. This uses a separate certificate for `tunnel.freewire.com`.

Same setup as `vpn.freewire.com` — Let's Encrypt with DNS-01 challenge, automatic renewal, stored in AWS Secrets Manager.

The DNS protocol itself (port 53 UDP) does not use TLS — DNS queries are not HTTPS. The certificate here is only for the DNS server management interface.

---

## 3. Self-Hosted Server Dashboard — Self-Signed Certificate

Self-hosted servers generate a self-signed certificate on first boot for their web dashboard (`https://<server-ip>:8443`). The Freewire client app accepts this certificate when importing a server config.

### Generation (on first boot)

The `freewire-server` binary generates the certificate itself:

```go
// Pseudocode — actual implementation in server/internal/tls/selfsigned.go
cert, key := tls.GenerateSelfSignedCert(
    commonName:  serverPublicIP,
    daysValid:   3650,   // 10 years — self-hosted servers may run for years
    keyType:     ecdsa.P256,
)
os.WriteFile("/etc/freewire/dashboard.crt", cert, 0644)
os.WriteFile("/etc/freewire/dashboard.key", key, 0600)
```

The certificate's fingerprint is embedded in the QR code and config file that users scan to connect their devices. The Freewire client pins to this fingerprint for self-hosted connections — it does not validate against system trust roots (the server has no registered domain, so CA validation would always fail).

**Fingerprint format in config:**
```
[Peer]
PublicKey = <wireguard-public-key>
Endpoint = 54.210.13.7:51820
DashboardFingerprint = sha256:<base64-encoded-sha256-of-der-cert>
```

The client displays a truncated version of this fingerprint in the Settings → My Server screen so the user can verify it matches the dashboard.

### Rotation

No automatic rotation. If a self-hosted server is re-deployed (new CloudFormation stack), a new keypair and certificate are generated. Connected devices show SELFHOST-4 (server key mismatch) and must re-import the new config. This is documented in the server web dashboard.

---

## 4. macOS Developer ID Certificate

Used to sign and notarize the macOS direct download app. Without this, Gatekeeper blocks the app on default macOS settings.

### Setup (one-time)

1. In Xcode → Settings → Accounts: log in with the Apple Developer account
2. Xcode → Manage Certificates → Create "Developer ID Application" certificate
3. The certificate and private key are stored in the macOS Keychain on the machine that created them
4. Export the certificate + private key as a `.p12` file for use in CI:
   ```
   Keychain Access → My Certificates → Developer ID Application: Freewire Inc
   → Export → .p12 format → set password
   ```
5. Store the `.p12` and password in GitHub Actions secrets or a secrets manager

### CI usage (GitHub Actions)

```yaml
- name: Import Developer ID certificate
  uses: apple-actions/import-codesign-certs@v3
  with:
    p12-file-base64: ${{ secrets.DEVELOPER_ID_P12_BASE64 }}
    p12-password: ${{ secrets.DEVELOPER_ID_P12_PASSWORD }}
```

### Renewal

Developer ID certificates are valid for 5 years. Apple sends email reminders at 180 and 30 days before expiry. Renew before expiry — builds signed with an expired certificate after the expiry date are still valid (Apple timestamps the signature), but new builds cannot be signed.

**Important:** When renewing, the new certificate has a different serial number. The app continues to work for existing users — code signatures are not re-verified on every launch. Only new downloads use the new certificate.

---

## Certificate Inventory

Keep this table updated as certificates change.

| Certificate | Domain / Use | Expiry | Auto-renew | Owner |
|---|---|---|---|---|
| Let's Encrypt | `vpn.freewire.com` | Every 90 days | Yes (acme.sh) | DevOps |
| Let's Encrypt | `tunnel.freewire.com` | Every 90 days | Yes (acme.sh) | DevOps |
| Self-signed | Self-hosted dashboards | 10 years (per deploy) | No | Auto-generated |
| Developer ID | macOS app signing | 5 years | No (manual) | Engineering |
