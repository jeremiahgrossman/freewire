# Freewire VPN — Privacy Policy

**Effective date:** [To be set before launch]  
**Last updated:** 2026-06-17

---

Freewire is a VPN application for iOS and macOS. This policy explains what data Freewire collects, what it doesn't, and why.

The short version: Freewire is designed to know as little about you as possible. Most of the privacy protections described here are architectural — not just promises, but technical constraints that prevent us from collecting data we don't need.

---

## Who we are

Freewire Inc., [address to be added before launch]. Contact: privacy@freewire.com.

---

## What Freewire does not collect

This section matters as much as what we do collect.

**No accounts.** Freewire does not require you to create an account, provide an email address, or identify yourself in any way. You can download and use Freewire without telling us who you are.

**No IP address logs.** When you connect to a Freewire server, your IP address is not recorded. Not at connection time, not in error logs, not anywhere. This is a technical constraint in our server software — IP logging is absent from the codebase, not merely disabled by policy.

**No connection logs.** We do not record when you connected, how long you were connected, or how much data you transferred. We cannot tell you when your device last connected to our servers, because we don't store that information.

**No traffic content.** Freewire carries an encrypted tunnel between your device and our servers. We cannot read what you send or receive: the contents of your traffic are encrypted end to end with the sites you visit, and we do not hold those keys.

**We can see where your traffic goes, and we do not record it.** This is worth stating plainly, because an earlier version of this policy said we could not, and that was wrong. A VPN server forwards your packets to their destination, so it necessarily knows the destination address — that is what forwarding means, and no VPN can avoid it. Today our servers can also see the hostname you asked for, because TLS still sends it in the clear. Encrypted Client Hello does not change this: ECH is negotiated between your browser and the destination site, not by anything in the middle of the connection, so no VPN — including this one — can add it on your behalf. None of this is written down regardless: connections are counted in hourly totals, never logged individually, and there is nothing on our servers that could later say which sites a device visited.

**If you want a provider that cannot know where you go,** no single-hop VPN can offer that, ours included. It takes two independent operators — one that knows who you are and not where you went, another that knows where you went and not who you are — as used by systems like iCloud Private Relay and Tor.

**No DNS query logs.** Even on the DNS tunnel path — where your VPN traffic is encoded into DNS queries to our servers — we do not log the content of those queries. The DNS labels carry encrypted payload; the content is invisible to us without the ephemeral session key, which we never retain.

**No device identifiers.** Freewire does not collect your device's UDID, advertising identifier (IDFA), or any other hardware or system identifier.

---

## Your device identity

Freewire identifies your device by a WireGuard cryptographic public key. This key is generated locally on your device at first launch and is never linked to your name, email, Apple ID, or any real-world identity.

The public key is a 44-character string that lets your device authenticate to Freewire's servers without revealing who you are.

If you uninstall and reinstall the app, a new key is generated. Your previous key becomes inactive.

**Multi-device:** If you use Freewire on multiple devices, each device has its own independent key. There is no account linking them.

---

## Data we do collect

### Anonymous rate-limiting tokens (Privacy Pass)

To prevent abuse of our free service, Freewire uses a privacy-preserving rate-limiting mechanism called **Privacy Pass** (an IETF standard). Here is how it works:

1. Your device requests a batch of anonymous tokens from our servers. The server signs the tokens without being able to see their final form — this is called blind signature cryptography.
2. Your device uses one token each time it connects. The server verifies the token's signature but cannot determine which device it came from.
3. After a token is used, we store a record that it was spent — to prevent it from being used twice. This record is a cryptographic hash of the token only. It cannot be linked to your device or to any identity.
4. Spent token records are deleted after 30 days.

The Privacy Pass design means we cannot answer "how many times has this device connected?" or "which tokens did this device receive?" — the mathematics of blind signatures make it structurally impossible to reconstruct this information.

### Aggregate performance metrics

We collect aggregate, anonymized performance statistics for capacity planning and reliability monitoring:

- Peak concurrent connections per server per hour
- Median and 95th-percentile tunnel latency per server per hour

These are rolled up in real time. No per-device or per-connection measurements are ever written to storage. We cannot reconstruct individual sessions from these metrics.

### Captive portal intelligence — evaluated, not offered

An earlier draft of this policy described an opt-in feature that would report which connection method worked on a given wifi network, to help other users on the same network connect faster. That feature was evaluated and deliberately not built: reconnect already remembers the last working method for a network, which covers most of the benefit, and a hashed wifi access point address is still a location identifier that public wardriving databases can reverse by lookup. There is no such setting in Freewire today, and nothing about your connection method is ever sent anywhere.

---

## Self-hosted servers

If you run your own Freewire server (self-hosted), Freewire's infrastructure plays no role in your VPN usage. Your device communicates directly with your own server. We have no record of your server's existence, the devices connected to it, or its usage.

When you first set up a self-hosted server using our AWS CloudFormation template, Freewire's servers are not contacted. The setup is entirely between your device, your AWS account, and the server software running on your infrastructure.

---

## Third-party services

**AWS:** Freewire's managed servers run on Amazon Web Services in the United States. AWS processes network traffic in transit but does not have access to unencrypted tunnel content. See AWS's privacy policy at aws.amazon.com/privacy.

**Cloudflare 1.1.1.1 (DNS):** DNS queries from your device while connected to Freewire are resolved by Cloudflare's 1.1.1.1 service using DNS over HTTPS. This applies Cloudflare's privacy policy to your DNS queries. We selected Cloudflare 1.1.1.1 because of their commitment to not retaining query logs. See 1.1.1.1/privacy-policy.

**Crash reporting:** [To be determined before launch — if a crash reporter is used, describe it here. Any crash reporter must be configured to exclude device identifiers and IP addresses.]

Freewire does not use advertising networks, analytics SDKs, or any third-party tracking tools.

---

## Data we cannot provide even if asked

By design, Freewire cannot truthfully provide the following in response to a legal request, subpoena, or government demand — not because we refuse, but because the data does not exist:

- Whether a specific person or IP address has ever used Freewire
- When a specific device last connected
- What websites a Freewire user visited
- How long a user was connected
- Which device a specific Privacy Pass token was issued to

We will comply with valid legal process. We will provide what we have. In most cases, what we have is: nothing that identifies you.

---

## Data retention summary

| Data | Retention |
|---|---|
| Spent Privacy Pass token hashes | 30 days, then deleted |
| Aggregate server metrics (hourly rollups) | 12 months, then deleted |
| Network intelligence reports (opt-in) | 6 months after last update per network, then deleted |
| Connection logs | Not collected — nothing to retain |
| IP addresses | Not collected — nothing to retain |

---

## Your rights

Depending on your location, you may have rights to access, correct, delete, or export personal data we hold about you. Because Freewire is designed to hold no personal data, there is generally nothing to access, correct, or delete. If you believe we hold data about you and wish to make a request, contact privacy@freewire.com.

**California residents (CCPA):** Freewire does not sell personal information. Freewire does not share personal information with third parties for cross-context behavioral advertising.

**European residents (GDPR):** Freewire's lawful basis for any data processing is legitimate interest (aggregate metrics for service reliability). For questions about GDPR rights, contact privacy@freewire.com.

---

## Changes to this policy

If we make material changes to this policy, we will post an updated version at freewire.com/privacy and, where required by law, notify you via the app. Material changes include: new categories of data collection, new third-party data sharing, or changes that reduce your privacy protections.

Non-material changes (clarifications, formatting, legal contact updates) will be made without notice.

---

## Contact

Questions about this policy: privacy@freewire.com  
Mailing address: [To be added before launch]

---

*Freewire VPN is designed so that protecting your privacy requires no trust in us — the architecture makes most of these protections automatic. This policy documents what we have built, not just what we promise.*
