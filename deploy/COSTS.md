# Hosting cost, and why it changes with users

For one user this is a rounding error. It stops being one quickly.

## Compute is not the cost

| Instance | Monthly |
|---|---|
| Lightsail (2 TB bundled) | $5 |
| EC2 t4g.small | ~$12 |

## Bandwidth is

AWS meters outbound at **$0.09/GB** past 100 GB/month. A VPN pays for the
user's entire internet session, so this scales directly with real usage.

| Users | 50 GB each | Monthly egress |
|---|---|---|
| 1 | 50 GB | $0 (inside free tier) |
| 100 | 5 TB | ~$450 |
| 1,000 | 50 TB | ~$4,500 |
| 10,000 | 500 TB | ~$45,000 |

50 GB/month is conservative for a default-on VPN; an evening of video is
5–10 GB.

## Providers that bundle transfer

| Provider | Monthly | Included | Overage |
|---|---|---|---|
| Hetzner CX22 | ~€4 | 20 TB | ~€1/TB |
| Lightsail | $5 | 2 TB | $0.09/GB |
| DigitalOcean | $6 | 1 TB | $0.01/GB |
| EC2 t4g.small | ~$12 | 100 GB | $0.09/GB |

Hetzner includes 200× the transfer of EC2 for a third of the price. That is
a different business model, not a tuning difference — and the Edge scanner
fleet already uses providers of this kind.

## If this ever serves anyone else

Split by what each is good at: control plane on AWS (API, Route 53, S3 for
the update feed — low bandwidth, good tooling), tunnel egress on
bundled-transfer hosts. `cloudformation-spec.md` stays valid regardless,
because there the user pays their own bill.

**Abuse matters more than cost.** A free VPN with no accounts attracts spam,
credential stuffing and infringing traffic; complaints go to the host, and
hosts terminate VPN operators routinely. Privacy Pass gives rate limiting
without identity, but a written abuse posture needs to exist before anyone
else is on the service, not after the first complaint.
