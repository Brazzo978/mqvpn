# iperf diagnostics for the MQVPN Android PoC

The provisioner installs this companion automatically. For an existing compatible
MQVPN VPS, run `sudo sh install.sh` from this directory.

`mqvpn-iperf` listens on **10.88.0.1:5201 inside the authenticated tunnel**.
It accepts TCP and UDP, upload and download, one test at a time. It restarts
with MQVPN and after a VPS reboot. The phone profile uses this endpoint.
No public iperf port is needed. The full phone setup uses 10.88.0.0/24;
standalone deployments with another subnet must adapt the service bind and client.

Check: `systemctl status mqvpn-iperf`, `journalctl -u mqvpn-iperf`.
Disable: `systemctl disable --now mqvpn-iperf`.
