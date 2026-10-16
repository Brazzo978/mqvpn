# MQVPN tunnel management companion

This Python 3 standard library service changes only three server settings:
`[Multipath] Scheduler`, `[Multipath] CC`, and `[Interface] MTU`. It binds
only to `10.88.0.1:9443`, the server's MQVPN tunnel address. It has no
public listener. The existing VPN already encrypts this path.

Install on the Debian VPS after MQVPN and `/etc/mqvpn/server.conf` exist:

```sh
cd /path/to/server/management
sudo sh install.sh
```

The installer preserves the existing config and adds
`[Control] Listen = 127.0.0.1:9090` when absent. It refuses an existing
different control listener, restarts `mqvpn-server.service`, then enables
`mqvpn-management.service`. The restart drops current tunnels. Both the
native control socket and this companion must remain private to their bind
addresses. The companion reads `[Auth] Key` directly; no second secret is
created and the key is never returned in an API response.

## Wire protocol

Use one UTF-8 JSON object followed by LF per TCP connection, with one LF
terminated JSON reply. The request is limited to 4096 bytes and 5 seconds.
Every request, including GET, must be authenticated:

```json
{"version":1,"op":"get","ts":1792060000,"nonce":"00112233445566778899aabbccddeeff","mac":"<64 lowercase hex>"}
```

For SET, add `"desired":{"scheduler":"minrtt","cc":"bbr2","mtu":1382}`
before calculating `mac`. Allowed schedulers are `wlb`, `minrtt`,
`wlb_udp_pin`, and `backup_fec` only when FEC is reported by
`get_build_info`. Allowed CC values are `bbr2`, `bbr`, and `cubic`.
MTU is an integer from 1280 through 9000. All three fields are required;
unknown fields and duplicate JSON keys are rejected.

MAC input is the request object without `mac`, serialized as UTF-8 JSON
with lexicographically sorted keys, no whitespace, and non-ASCII characters
left unescaped (`json.dumps(sort_keys=True, separators=(',', ':'),
ensure_ascii=False)`). Use HMAC-SHA256 and the literal `[Auth] Key` text
as UTF-8 key bytes. Send lowercase hex. Timestamps are Unix seconds within
60 seconds of the server clock; the nonce is 16 random bytes in lowercase
hex and cannot be reused during the replay window. Do not log the PSK or
request MAC.

A successful reply includes `ok`, `capabilities`, `desired`,
`applied`, `observedScheduler`, `status`, `requiresReconnect`, and
`error`. `desired` is read from disk. `status=pending` means the
asynchronous restart has not completed and `requiresReconnect=true`.
The server waits two seconds after sending this response before restarting
MQVPN; the tunnel will drop. The delay can be set from 0 to 10 seconds with
`--restart-grace-sec` in the systemd unit. Reconnect the client, then GET until `status=applied` with all three
`applied` values matching the request. An initial GET may report
`status=unknown`; SET of the same values then performs a verifying restart.
Subsequent SET of already verified values does not restart.

The companion reports `applied` only after `systemctl restart`, active
service status, and the native `get_build_info` scheduler agree. The native
control API does not expose live CC or MTU, so their applied values are
**inferred from the configuration loaded by the verified restart**, rather
than observed independently. An external config edit or scheduler mismatch
changes status to `unknown`. A failed restart restores the previous config,
restarts MQVPN again, and reports `failed`; inspect the service journal if
rollback restart also fails. Before editing, the companion saves a mode-0600
`server.conf.management-backup` and a pending state record. If the companion
exits during apply, its next start restores that backup and restarts MQVPN.
The backup is removed after successful apply or rollback.

## Validation

```sh
python3 -m unittest -v test_management.py
systemctl status mqvpn-server mqvpn-management
ss -ltn | grep -E '127.0.0.1:9090|10.88.0.1:9443'
```

The unit can start before the tunnel address exists; systemd retries
binding every two seconds. There is no active remote management until the
tunnel is up. Changing either service's bind address requires editing the
unit and is outside the API.
