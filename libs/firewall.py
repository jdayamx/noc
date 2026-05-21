import platform
import subprocess
import re

def check_ufw():
    if platform.system() == "Windows":
        return None

    try:
        output = subprocess.check_output(['which', 'ufw'], stderr=subprocess.STDOUT)
        if output:
            return "ufw is installed"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None

def check_firewalld():
    if platform.system() == "Windows":
        return None

    try:
        result = subprocess.run(
            ['systemctl', 'is-active', '--quiet', 'firewalld'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            version_output = subprocess.check_output(['firewall-cmd', '--version'], stderr=subprocess.STDOUT)
            version = version_output.decode('utf-8').strip()
            return f"firewalld is installed, version: {version}"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None

def check_iptables():
    if platform.system() == "Windows":
        return None

    try:
        output = subprocess.check_output(['iptables', '--version'], stderr=subprocess.STDOUT)
        version = output.decode('utf-8').strip()
        return f"iptables is installed, version: {version}"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None

def has_iptables():
    return check_iptables() is not None

def get_firewall_type():
    if has_iptables():
        return "iptables"
    if check_firewalld():
        return "firewalld"
    if check_ufw():
        return "ufw"
    return None

def check_windows_firewall():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(['powershell', 'Get-NetFirewallProfile'], stderr=subprocess.STDOUT, timeout=1)
            if "Enabled" in output.decode('utf-8'):
                return "Windows Firewall is installed and active"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        except subprocess.TimeoutExpired:
            pass
    return None

def check_firewall():
    firewalls = [
        check_ufw(),
        check_firewalld(),
        check_iptables(),
        #check_windows_firewall(),
    ]
    
    # Збираємо всі знайдені файрволи в список
    installed_firewalls = [fw for fw in firewalls if fw]
    
    if installed_firewalls:
        return ", ".join(installed_firewalls)  # Повертаємо список файрволів з їх версіями
    return "No firewall detected"

def _parse_iptables_listing(output, table_name):
    tables = []
    current_chain = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("Chain "):
            if current_chain:
                tables.append(current_chain)

            chain_match = re.match(r"^Chain\s+(\S+)\s+\((.*)\)$", line)
            if not chain_match:
                continue

            current_chain = {
                "name": chain_match.group(1),
                "details": chain_match.group(2),
                "rules": [],
            }
            continue

        if line.startswith("num "):
            continue

        if current_chain and line[0].isdigit():
            parts = line.split()
            if len(parts) >= 10:
                current_chain["rules"].append({
                    "num": parts[0],
                    "pkts": parts[1],
                    "bytes": parts[2],
                    "target": parts[3],
                    "prot": parts[4],
                    "opt": parts[5],
                    "in": parts[6],
                    "out": parts[7],
                    "source": parts[8],
                    "destination": parts[9],
                    "extra": " ".join(parts[10:]),
                })

    if current_chain:
        tables.append(current_chain)

    return {
        "name": table_name,
        "chains": tables,
    }

def get_iptables_tables():
    if platform.system() == "Windows":
        return []

    tables = []
    for table_name in ("filter", "nat", "mangle", "raw", "security"):
        try:
            output = subprocess.check_output(
                ["iptables", "-t", table_name, "-L", "-n", "-v", "--line-numbers"],
                stderr=subprocess.STDOUT,
                text=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

        parsed = _parse_iptables_listing(output, table_name)
        if parsed["chains"]:
            tables.append(parsed)

    return tables
