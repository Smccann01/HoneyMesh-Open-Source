# HoneyMesh Exchange deployment modes

This page describes the current product boundary. An Exchange is a service that receives and distributes eligible observations. A direct HoneyMesh mesh is a separate, operator-approved relationship between nodes. Neither relationship grants automatic remote enforcement.

| Path | Current access | Operator control | Status |
|---|---|---|---|
| Free HoneyMesh Core pilot and direct mesh | No Network Decode subscription | Each operator configures local identity, trusted peers, sharing, and enforcement | Available for bounded, noncritical evaluation |
| Customer-operated Exchange | Free AGPL-3.0-only Exchange source; no Network Decode subscription | Customer runs the service, database, administrators, enrollment, and sharing policy | Available as source; production installer and recovery qualification remain open |
| Network Decode hosted Exchange | Separate $5 USD per enrolled node per month, in addition to the current $45 HoneyMesh 2.0 node package | Subscriber chooses whether to publish, receive, and act locally | Hosted subscription checkout is being prepared; see the [current offer](https://network-decode.com/products/honeymesh-exchange) |
| Private Exchange to hosted Exchange federation | Would need separate authorization and a hosted entitlement for each node consuming commercial intelligence | Customer must explicitly approve what crosses the boundary | Planned; no supported federation gateway today |

## Customer-operated Exchange

The administrator creates credentials locally, issues a short-lived one-use enrollment token, and enrolls nodes at that Exchange's own HTTPS origin. No hosted billing account, Network Decode license server, or `honeymesh.io` connection is required for this path. Sharing and discovery start off. Receiving nodes keep their own policy and may treat observations as review-only. See [machine API v1](MACHINE_API_V1.md) and the [Exchange setup](../README.md).

## Hosted Exchange

Network Decode controls access to its own hosted intelligence service. Its current commercial enrollment path requires a licensed HoneyMesh 2.0 node identity and an active hosted seat. The $45 package purchase does not buy a hosted seat. Loss of a hosted seat must not disable local detection, local firewall policy, or an independently operated private Exchange. Public web pages explain the service and subscription path; they do not expose subscriber observations or network activity.

## Federation boundary

Direct node-to-node mesh trust is not an Exchange-to-Exchange federation gateway. A future gateway needs explicit publication and receipt policies, authenticated Exchange and node identities, provenance, replay prevention, loop prevention, revocation, audit, and a verifiable count of commercial-intelligence consumers. A single gateway connection cannot stand in for unlimited paid hosted nodes. No private Exchange sends observations to Network Decode solely because it is installed or because a local node enrolls in it.
