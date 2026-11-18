import { createGuardCore, isEligibleSource, REASON_CODES } from "./guard-core.mjs";

export { isEligibleSource, REASON_CODES };

/** Standalone application protection. It cannot create host or XDP grants. */
export function createNodeGuard(options = {}) {
  return createGuardCore(options);
}

/** Existing pilot API; local enforcement is free and retains source safeguards. */
export function createHoneyMeshGuard(options = {}) {
  return createGuardCore(options);
}
