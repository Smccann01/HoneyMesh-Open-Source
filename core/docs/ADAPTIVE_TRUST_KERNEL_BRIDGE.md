# Adaptive Trust to kernel bridge candidate

Status: source-level, opt-in candidate on the `honeymesh-2.0` branch. No Core runtime, dashboard route, or external request calls this bridge. Ordinary tests use the UEE's fake kernel adapter. The opt-in `TestAdaptiveTrustRealKernelMap` loads the actual eBPF collection and verifies the UEE map write and expiry on a disposable privileged Linux host; it does not attach XDP to an interface or test packet drops.

`internal/adaptivetrustkernel.ApplyQuarantine` is restricted to `host-network` / `network.quarantine`. It reads a durable local HAT hold and audited decision, requires a separately approved, verified, exclusive source-IP binding for the same tenant and subject, and creates an exact-IP local owner in the Unified Enforcement Engine (UEE). The owner has a lease of at most 30 seconds. The result reports the UEE's confirmed kernel state; in TEST mode it reports no kernel block.

Ordinary HAT `deny`, `verify`, or `restrict` decisions for an application route cannot create an IP block. XDP can block the source address; it cannot enforce a user permission or one API action. A shared IP, NAT address, or uncertain identity is not eligible for this bridge.

The binding structure is a contract for a future trusted local verifier, **not** evidence by itself. The caller must authenticate the operators, verify address exclusivity and its expiry, and bind the subject to that address before calling the bridge. A source-IP binding must be persisted and revocable. A released hold must promptly remove only its HAT UEE owner; the current short lease is an upper bound, not the intended recovery workflow. These requirements, a secure runtime API, and real XDP host tests are release gates. Do not enable this bridge for live traffic until they pass.

Run the privileged map test only on a disposable host: `HONEY_KERNEL_INTEGRATION=1 go test -run '^TestAdaptiveTrustRealKernelMap$' -count=1 .`.
