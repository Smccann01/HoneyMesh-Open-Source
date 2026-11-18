# Node Guard Next.js Route Handler candidate

**Status:** private `0.2.0-alpha.6` adapter candidate. Tests cover Web `Request`/`Response` behavior. A clean Next.js deployment, trusted ingress, and restart/load tests remain open.

The installed Next.js 16.4.3 guide defines App Router Route Handlers in `app/**/route.js|ts` using Web `Request` and `Response`. Its Node.js runtime is the default. This package imports Node APIs and is not an Edge adapter. The guide also warns that the `runtime` route export should be removed when Cache Components are enabled; no `runtime` export is needed in the example below.

```js
// app/api/login/route.js — shape only; provide the source callback for your deployment.
import { createNextRouteGuard } from "@honeymesh/node-guard/next-route";
import { guard } from "./guard-instance.js";
import { getVerifiedSourceIpFromDeployment } from "./trusted-ingress.js";

const check = createNextRouteGuard({
  guard,
  getVerifiedSourceIp: getVerifiedSourceIpFromDeployment,
});

export async function POST(request) {
  const restriction = await check(request);
  if (restriction) return restriction;
  // Authenticate normally. Record a v1 observation only after a real failure.
  return Response.json({ ok: true });
}
```

The application must supply a verified source through a deployment-specific trust boundary. A standard Web `Request` does not expose the socket peer, so copying `request.headers.get("x-forwarded-for")` into the callback is unsafe. The callback may be asynchronous. If it fails or returns no source, the adapter returns 503; `THROTTLE` returns 429 and `DENY` returns 403 with `Retry-After` and `Cache-Control: no-store`.

Create one v1 policy runtime for the exact application and route ID and share it only within a persistent single Node process. Do not claim consistent thresholds when a serverless platform starts multiple instances or a load balancer spreads traffic across replicas. A shared-state adapter and deployment-specific source verification are later qualification work.
