import { createHmac, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateObservationV1 } from '@network-decode/node-guard/policy';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const { webhookSecret } = JSON.parse(await readFile(join(root, '.local', 'credentials.json'), 'utf8'));
const sourceIp = process.argv[2] ?? '8.8.8.8';
const eventId = randomUUID();
const observation = validateObservationV1({
  schema_version: 1, application_id: 'firewall-lab', event_id: eventId,
  observed_at: new Date().toISOString(), route_id: 'auth.login',
  reason_code: 'authentication_failure', source_ip: sourceIp, protocol: 'HTTP',
});
const rawBody = Buffer.from(JSON.stringify(observation));
const timestamp = String(Math.floor(Date.now() / 1_000));
const signature = createHmac('sha256', webhookSecret)
  .update('nodeguard-webhook-v1\n').update(timestamp).update('\n')
  .update(eventId).update('\n').update(rawBody).digest('hex');
const port = Number(process.env.LAB_PORT ?? 8787);
const response = await fetch(`http://127.0.0.1:${port}/webhooks/observation`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-ng-timestamp': timestamp,
    'x-ng-event-id': eventId, 'x-ng-signature': signature },
  body: rawBody,
});
const result = await response.json();
process.stdout.write(`${JSON.stringify({ status: response.status, result }, null, 2)}\n`);
if (!response.ok) process.exitCode = 1;
