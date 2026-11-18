export interface NodeEntitlement {
  schema_version: 1;
  product: "node_guard" | "node_pro";
  subscription_id: string;
  unit_id: string;
  expires_at: string;
  signature: string;
}
export declare function verifyNodeEntitlement(document: unknown, expectedProduct: "node_guard" | "node_pro", expectedUnitId: string, now?: number): boolean;
export declare function verifyEntitlementWithKey(document: unknown, expectedProduct: "node_guard" | "node_pro", expectedUnitId: string, publicKey: string, now?: number): boolean;
