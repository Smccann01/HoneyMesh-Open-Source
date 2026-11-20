# HoneyMesh Node Guard Tools Snap

This strict Snap contains the policy CLI from the free Node Guard SDK. It is a
local development and evaluation tool. It does not install the SDK into an
application, run a network daemon, or protect traffic on its own. The Snap is
limited to AMD64 while its first installed build is qualified.

Install the beta with `sudo snap install network-decode-nodeguard --beta`.
The current step-by-step manual is at
<https://network-decode.com/docs/node-guard-snap>. It links back to the
[Snap Store listing](https://snapcraft.io/network-decode-nodeguard) and the
separate SDK integration guide.
Run `network-decode-nodeguard init` from a directory in your home folder to
create an OBSERVE policy, then use `network-decode-nodeguard doctor
nodeguard.policy.json` and `network-decode-nodeguard policy validate
nodeguard.policy.json`. Use `policy test` with synthetic observations before
integrating the SDK into a real Node.js process. Read the component
[README](../README.md) for trusted-source and integration boundaries.

The Snap uses the `home` interface to read and write policy files in a user's
non-hidden home directory. It does not request network or firewall access.
