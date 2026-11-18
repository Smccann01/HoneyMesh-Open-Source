#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  if [[ -n "${hm_pid:-}" ]]; then kill "$hm_pid" 2>/dev/null || true; fi
  ip netns delete hmclient 2>/dev/null || true
  ip link delete hmhost 2>/dev/null || true
}
trap cleanup EXIT

groupadd -r honeymesh
useradd -r -g honeymesh -d /var/lib/honeymesh -s /usr/sbin/nologin honeymesh
install -d -m 0700 -o honeymesh -g honeymesh /var/lib/honeymesh
install -d -m 0750 -o root -g honeymesh /etc/honeymesh
cp /pkg/honeymesh.community.json /etc/honeymesh/honeymesh.json
chown root:honeymesh /etc/honeymesh/honeymesh.json
chmod 0640 /etc/honeymesh/honeymesh.json
sh /pkg/init-local-certs.sh /etc/honeymesh/certs >/dev/null
chgrp honeymesh /etc/honeymesh/certs /etc/honeymesh/certs/ca /etc/honeymesh/certs/node /etc/honeymesh/certs/ca/ca.crt /etc/honeymesh/certs/node/node.crt /etc/honeymesh/certs/node/node.key
chmod 0750 /etc/honeymesh/certs /etc/honeymesh/certs/ca /etc/honeymesh/certs/node
chmod 0640 /etc/honeymesh/certs/ca/ca.crt /etc/honeymesh/certs/node/node.crt /etc/honeymesh/certs/node/node.key

ip netns add hmclient
ip link add hmhost type veth peer name hmpeer
ip link set hmpeer netns hmclient
ip address add 10.77.0.1/24 dev hmhost
ip link set hmhost up
ip netns exec hmclient ip address add 10.77.0.2/24 dev hmpeer
ip netns exec hmclient ip link set lo up
ip netns exec hmclient ip link set hmpeer up

node - <<'JS'
const fs=require('fs');
const p='/etc/honeymesh/honeymesh.json';
const c=JSON.parse(fs.readFileSync(p));
c.interfaces=['hmhost'];
c.traps={'21': {enabled:true,proto:'tcp',banner:'HoneyMesh test\r\n'}};
c.security.allowlist_base=false;
c.security.trap_ban_hits=2;
fs.writeFileSync(p,JSON.stringify(c));
JS
chown root:honeymesh /etc/honeymesh/honeymesh.json
chmod 0640 /etc/honeymesh/honeymesh.json

setpriv --reuid honeymesh --regid honeymesh --init-groups \
  --inh-caps +bpf,+perfmon,+net_admin,+net_raw,+net_bind_service \
  --ambient-caps +bpf,+perfmon,+net_admin,+net_raw,+net_bind_service \
  --nnp /usr/local/bin/honeymesh -config /etc/honeymesh/honeymesh.json -state-dir /var/lib/honeymesh >/tmp/hm236.log 2>&1 &
hm_pid=$!
sleep 5
kill -0 "$hm_pid"
awk '/^(Uid|Gid|Groups|CapEff|NoNewPrivs):/ {print}' "/proc/$hm_pid/status"
test "$(curl -ksS -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/health)" = 200
ip -details link show hmhost | grep 'prog/xdp'
token=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync("/var/lib/honeymesh/runtime-state.json")).admin_token)')
test "$(curl -ksS -o /dev/null -w '%{http_code}' -X POST -H "X-Honey-Token: $token" -H 'Content-Type: application/json' -d '{"name":"hmhost","enable":false}' https://127.0.0.1:8443/api/iface)" = 200
if ip -details link show hmhost | grep -q 'prog/xdp'; then echo 'XDP detach failed' >&2; exit 1; fi
test "$(curl -ksS -o /dev/null -w '%{http_code}' -X POST -H "X-Honey-Token: $token" -H 'Content-Type: application/json' -d '{"name":"hmhost","enable":true}' https://127.0.0.1:8443/api/iface)" = 200
ip -details link show hmhost | grep 'prog/xdp'
node -e 'if(JSON.parse(require("fs").readFileSync("/var/lib/honeymesh/runtime-state.json")).interfaces.join()!=="hmhost")process.exit(1)'
test "$(curl -ksS -o /dev/null -w '%{http_code}' -X POST -H "X-Honey-Token: $token" -H 'Content-Type: application/json' -d '{"mode":"ENFORCE"}' https://127.0.0.1:8443/api/mode)" = 200
probe() {
  if timeout 2 ip netns exec hmclient bash -c 'echo >/dev/tcp/10.77.0.1/21' 2>/dev/null; then echo connected; else code=$?; if [[ "$code" -eq 124 ]]; then echo timeout; else echo "error:$code"; fi; fi
}
first=$(probe); sleep 1
second=$(probe); sleep 1
third=$(probe)
echo "probes=$first,$second,$third"
test "$first" = connected
test "$second" = connected
test "$third" = timeout
test "$(curl -ksS -o /dev/null -w '%{http_code}' -X POST -H "X-Honey-Token: $token" -H 'Content-Type: application/json' -d '{"ip":"10.77.0.2","reason":"service-user test"}' https://127.0.0.1:8443/api/allow)" = 200
test "$(probe)" = connected
echo 'service_user_xdp_lowport_ban_unban=PASS'
