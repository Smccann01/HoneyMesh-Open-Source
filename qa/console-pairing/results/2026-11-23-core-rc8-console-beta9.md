# Published Core RC8 with Firewall Console beta.9

On 2026-11-23 (US Central; 2026-11-24 UTC), [GitHub Actions run 45327650454](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/45327650454) passed the Console/Core pairing workflow on a disposable Ubuntu 24.04 AMD64 VM with kernel `7.0.0-1017-azure`. The workflow downloaded each published release and checked its `SHA256SUMS` and GitHub attestation before installation.

| Published asset | SHA-256 |
| --- | --- |
| Core 2.3.6 RC8 Community 5 AMD64 DEB | `02d022fd98179701696c6342fdb92f767296334f6f00603395f800880aaa490f` |
| Firewall Console 0.2.1 beta.9 free pilot bundle | `85646123933ecb1c729da129987dece6896c2e02b778131371806c7fe1ff69ae` |

The report passed all eight grouped checks:

1. Core installed with safe defaults in TEST.
2. The Console account could read the certificate-pinned local agent.
3. Console host writes were denied by default.
4. The Console could not block in TEST after its scoped-action opt-in.
5. In ENFORCE on an isolated generic-XDP veth, a 60-second Console grant blocked one exact source, a second source stayed reachable, and Core's XDP drop count increased.
6. Scoped release restored traffic, the Console returned Core to TEST, and disabling scoped actions denied a new write.
7. After restoring the original configuration and restarting Core, its identity was unchanged and XDP was detached.
8. The Console was removed while Core state was retained.

An earlier attempt stopped with a Console connection error during release and recovery. The runner now records finer recovery stages and waits for the local service after disabling scoped actions; the rerun passed. The earlier error's exact cause was not established. This result proves only the scoped pilot behavior above. It does not qualify a physical or native-XDP NIC, packet rate, production reliability, other Linux releases, Node Pro's application bridge, or a browser user's full workflow. No public ingress interface was attached.
