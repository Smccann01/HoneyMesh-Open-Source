# Core and Node Snap developer candidates

These packages are **not** in the Ubuntu App Center. They are developer
candidates for the two XDP host agents. The CI builds each Snap, checks its
checksum, installs it in devmode, creates unique local state, verifies that
the Community configuration has no selected interfaces or sharing, and probes
XDP attach/detach on an isolated veth pair. Passing these tests does not
establish that enforcement works under strict confinement.

Each candidate must be installed with `--devmode --dangerous` from a CI
artifact, on a disposable Ubuntu 24.04 AMD64 host only. Neither package starts
a service on installation. Run `sudo snap run network-decode-core.init` or
`sudo snap run network-decode-node.init` to create private configuration and
certificates under `/var/snap/<snap-name>/common/`. Review the configuration
before running `sudo snap run <snap-name>` manually. Never select a critical
interface for an unqualified test.

Qualification before a Store beta:

1. Extend the isolated veth test to map update, crash, restart, and uninstall
   on a disposable host. Record actual kernel and snapd logs.
2. Resolve required BPF access under an approved Snap confinement model.
   Devmode is diagnostic and is not a release confinement model. Classic
   confinement requires Canonical review.
3. Prove config, certificates, and runtime state survive a Snap refresh;
   prove backup, rollback, and purge behavior.
4. Test on Ubuntu 24.04 AMD64, including unsupported-kernel and conflicting
   agent cases. Keep the default TEST mode and require local operator action
   before any enforcement.

Track Store readiness in [issue #31](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/31).
