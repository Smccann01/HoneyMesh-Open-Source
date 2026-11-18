import { createHmac, randomBytes } from "node:crypto";

const fallbackSalt = randomBytes(32);

export function activitySourceId(ip: string, at: Date = new Date()) {
  const configuredSalt = process.env.EXCHANGE_ACTIVITY_SALT;
  const key = configuredSalt && configuredSalt.length >= 32 && !configuredSalt.startsWith("REPLACE_") ? configuredSalt : fallbackSalt;
  const day = at.toISOString().slice(0, 10);
  return `HM-${createHmac("sha256", key).update(`${day}\0${ip}`).digest("hex").slice(0, 10).toUpperCase()}`;
}
