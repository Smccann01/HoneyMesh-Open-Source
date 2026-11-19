# HoneyMesh Console Snap beta

This is a strict, observation-only Snap beta for Ubuntu App Center. It
packages the free Firewall Console from this repository; it does not package or
install HoneyMesh Core, attach XDP, or enable host writes. The Snap binds only
to `127.0.0.1:8787` and stores local credentials in its private Snap data.
The square Store icon is a size-adjusted copy of `core/web/logo.png`, preserving
the project's bee mark shown on network-decode.com.

The public install and use manual is at
https://network-decode.com/docs/console-snap. Install the Store release with
`sudo snap install network-decode-console --beta`.

The `network-observe` plug may require an explicit connection before host
socket and interface snapshots are available:

```sh
sudo snap connect network-decode-console:network-observe
```

After installation, open `http://127.0.0.1:8787` on the same host. Obtain the
one-time local bootstrap token in your own terminal:

```sh
sudo python3 -c 'import json; print(json.load(open("/var/snap/network-decode-console/common/private/credentials.json"))["adminToken"])'
```

Create the local admin account with that token and a unique password of at
least 16 characters. Do not
send the token through support or post it publicly. The Console's account is
local; it is not a HoneyMesh license.

For a developer build, run `snapcraft` from the repository root, install the
resulting `.snap` with `sudo snap install --dangerous <file.snap>`, then inspect
`snap services network-decode-console` and `curl http://127.0.0.1:8787/health`.
The GitHub workflow builds and smoke-tests a candidate without publishing it.
The project publisher releases verified revisions to the beta channel.

Current limit: strict Snap confinement can restrict host `/proc` views and
agent integration. The installed-Snap test verified a bounded Linux socket and
interface snapshot after connecting `network-observe`; it does not establish
complete host visibility. Do not describe the Snap as protecting traffic or as
qualified for production.
