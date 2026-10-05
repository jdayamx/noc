# Fail2Ban UI systemd deployment

This folder contains a minimal standalone systemd setup for Fail2Ban UI on port `1984`.

## Service

Install the unit:

```bash
sudo cp deployment/fail2ban-ui/fail2ban-ui.service /etc/systemd/system/fail2ban-ui.service
sudo systemctl daemon-reload
sudo systemctl enable --now fail2ban-ui
```

The unit binds the web UI to `10.1.1.1:1984`, so it is reachable on `http://10.1.1.1:1984` only on that interface.

## Firewall helper

The companion firewall helper is expected at:

```text
/home/firewall/fail2ban-ui-1984.sh
```

It opens TCP port `1984` using `ufw`, `firewall-cmd`, or `iptables`, depending on what the host has installed.
