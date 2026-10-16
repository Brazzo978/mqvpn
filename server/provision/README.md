# MQVPN VPS setup and private phone profiles

Run on a **new Debian or Ubuntu VPS** (amd64 or arm64) as root, from a trusted checkout of this project. The VPS needs a public address, inbound UDP on the MQVPN port (443 by default), and outbound access to the pinned MQVPN v0.17.0 GitHub release. Review the release and firewall rules before running an installer on a production host. `setup.sh` invokes the existing pinned-release installer, then installs the management and iperf companions and creates the first native MQVPN user. It does not accept or print the global `[Auth] Key` used for server administration.

## Quick start: a new test VPS

Connect with SSH to an interactive terminal as root, then run the following commands.
If you log in as a regular user, enter a root shell with `sudo -i` first.
Replace `203.0.113.10` with your VPS public IPv4 address. Allow **UDP 443**
in the VPS provider firewall and in any host firewall. SSH access must stay allowed.

```sh
apt-get update
env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git ca-certificates curl bash python3 openssl qrencode iperf3 \
  iptables iproute2 procps tar coreutils

git clone --depth 1 --branch feat/android-vps-qr-setup \
  https://github.com/Brazzo978/mqvpn.git mqvpn-phone
cd mqvpn-phone

sh server/provision/setup.sh \
  --name phone1 --server-address 203.0.113.10 --insecure --show-qr
```

The script installs the upstream **v0.17.0** binaries after checking the release
SHA-256 manifest, configures forwarding/NAT, installs and enables the three
systemd services, creates a separate user credential, and displays its QR.
The wrapper suppresses the base installer's output because that output contains
the global administration key. A setup error exits with a nonzero status.

The `--insecure` option explicitly permits the self-signed TLS certificate for
this proof of concept. For a public deployment, use the trusted certificate
procedure below. This guide targets the Android PoC8 app (0.17.0-multipath-poc8)
with QR profile import; the generic upstream Android demo does not include it.

In the phone app, open **Import profile**, scan the QR, review the endpoint and
TLS option, then confirm the import. Select your connections and connect.
The profile always uses **MTU 1280**. The QR contains a personal key; scan it
privately and close the terminal when finished.

## Trusted TLS certificate

For a CA-trusted certificate already placed at `/etc/mqvpn/server.crt` with its private key at `/etc/mqvpn/server.key`:

```sh
sh server/provision/setup.sh --name alice --server-address vpn.example.com --tls-server-name vpn.example.com --show-qr
```

The bootstrap verifies that certificate's hostname and trust chain before creating a profile. The installer generates a self-signed certificate when no certificate exists. For a **test VPS only**, explicitly permit that certificate in the phone profile:

```sh
sh server/provision/setup.sh --name alice --server-address 203.0.113.10 --insecure --show-qr
```

Scan the QR privately in the Android app's profile importer. The QR carries Alice's personal PSK and must be treated like a password. `--show-qr` requires an interactive terminal; no QR or profile secret is printed by default. The provisioner saves each profile as a root-only JSON file in `/etc/mqvpn/profiles` (directory 0700, files 0600). Do not send those files to other users or include them in a shared backup.

## Multiple users

From the checkout directory, add a separate credential for each phone or user (up to 64 configured users). For additional users or routine administration on the VPS:

```sh
python3 server/provision/mqvpn_provision.py add bob --show-qr
python3 server/provision/mqvpn_provision.py list
python3 server/provision/mqvpn_provision.py export bob --show-qr
python3 server/provision/mqvpn_provision.py revoke alice
```

`add` is idempotent for an already managed user; it reuses the same PSK. `revoke` removes that user's server credential and private profile. `export` only shows the QR on a TTY. To reach the script from any directory, install a root-owned copy with `install -m 0755 server/provision/mqvpn_provision.py /usr/local/sbin/mqvpn-provision` and run `mqvpn-provision ...`.

## Profile format and administration

The QR uses `mqvpn://profile?data=<base64url UTF-8 JSON>`. It contains version 1, name, endpoint, TLS name, **user** `authKey`, MTU, control and iperf endpoint fields, `insecure`, and `serverControlAllowed:false`. The global `[Auth] Key` stays only in the server config. Personal users cannot change global server settings through the management API.

Adding or revoking a user atomically edits `server.conf`, restarts MQVPN, verifies the native user list, and starts management again. That restart briefly disconnects **all** active users, so schedule changes accordingly. A failed restart restores the previous config; a retained `server.conf.provision-backup` means recovery needs attention. After checking the failure and service status, run `python3 server/provision/mqvpn_provision.py recover`. Do not delete retained backups to force an update.

## Verify and troubleshoot

The setup uses **10.88.0.0/24**: the tunnel server address is 10.88.0.1.
An existing configuration on another subnet is rejected before companion services
are installed; it is not silently migrated. This setup is separate from the
OpenMPTCProuter VPS installer. Do not run it as an upgrade on an OMR VPS without
reviewing that deployment's service and network configuration.

| Endpoint | Purpose | Exposure |
| --- | --- | --- |
| UDP 443 | MQVPN tunnel | Public; allow inbound |
| TCP 127.0.0.1:9090 | Native control | Loopback only |
| TCP 10.88.0.1:9443 | Authenticated management | Tunnel only |
| TCP/UDP 10.88.0.1:5201 | iperf3 tests | Tunnel only |

Do not open 9090, 9443 or 5201 on the public firewall. To check health:

```sh
systemctl is-active mqvpn-server mqvpn-management mqvpn-iperf
ss -lntup
python3 server/provision/mqvpn_provision.py list
journalctl -u mqvpn-server -u mqvpn-management -u mqvpn-iperf -n 60 --no-pager
```

If `--show-qr` reports that a terminal is required, run the command directly in
your SSH terminal (use `ssh -t` for a remote command), without piping it to a file.
If the app cannot connect, check the public IP, UDP 443 firewall rule and certificate
mode first. If it connects but the speed test fails, check `mqvpn-iperf` and that
the profile's iperf endpoint is 10.88.0.1:5201.

Local automated checks cover user isolation, persistent config editing, rollback,
management authentication and subnet compatibility. Fresh-VPS installation and
an optical phone scan must still be checked on the actual target.
