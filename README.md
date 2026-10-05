
# Network Operation Center (NOC)

A simple and customizable Network Operations Center (NOC) built with Python, Flask, and Bootstrap.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jdayamx/noc.git
   cd noc
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Firewall Configuration

If you are using a firewall, allow the necessary ports:

- **For Ubuntu (ufw)**:
   ```bash
   sudo ufw allow 1983/tcp
   ```

- **For other systems (firewalld)**:
   ```bash
   sudo firewall-cmd --zone=public --add-port=1983/tcp --permanent
   sudo firewall-cmd --reload
   ```

## Fail2Ban Rule For Nginx Scanners

This repository includes a fail2ban filter and jail for noisy Nginx scan traffic:

- `fail2ban/filter.d/nginx-scan.conf`
- `fail2ban/jail.d/nginx-scan.local`

The jail is configured with:

- `maxretry = 1`
- `bantime = -1` for a permanent ban
- `action = iptables-allports`

Install it on the host by copying those files into `/etc/fail2ban/filter.d/` and `/etc/fail2ban/jail.d/`, then restart fail2ban:

```bash
sudo cp fail2ban/filter.d/nginx-scan.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/jail.d/nginx-scan.local /etc/fail2ban/jail.d/
sudo systemctl restart fail2ban
sudo fail2ban-client status nginx-scan
```

## Usage

1. Run the app:
   ```bash
   python noc.py
   ```

2. Access the dashboard in your web browser at:
   ```
   http://localhost:1983
   ```

## Features

- **Real-time monitoring** of system statistics (CPU, memory, network, etc.)
- **Customizable dashboard** with Bootstrap front-end.
- Easy integration with various server environments.
- Cross-platform support.

## Contributing

Feel free to open issues and create pull requests. Contributions are always welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
