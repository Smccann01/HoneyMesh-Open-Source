import { BlockList, isIP } from "node:net";

const deniedV4 = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24],
  ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) deniedV4.addSubnet(address, prefix, "ipv4");
const deniedV6 = new BlockList();
for (const [address, prefix] of [
  ["::", 128], ["::1", 128], ["::ffff:0:0", 96], ["fc00::", 7],
  ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32],
] as const) deniedV6.addSubnet(address, prefix, "ipv6");
const publicV6 = new BlockList();
publicV6.addSubnet("2000::", 3, "ipv6");

export function isPublicIndicator(raw: string) {
  const address = raw.trim();
  const family = isIP(address);
  if (family === 4) return !deniedV4.check(address, "ipv4");
  if (family === 6) return publicV6.check(address, "ipv6") && !deniedV6.check(address, "ipv6");
  return false;
}
