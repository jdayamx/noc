
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
